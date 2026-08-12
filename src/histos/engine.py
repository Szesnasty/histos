"""The decision engine — pure policy evaluation.

``pre()`` decides whether a call may execute; ``post()`` inspects the result and
redacts leaked/sensitive content. Both are **fail-closed**: any exception inside
a check becomes a DENY, never a silent allow.

The pre-gate chain (fail-fast), review-revised:

1. ``unknown_tool``     — no contract → deny-by-default
2. ``rbac``             — role allow-list
3. ``arg_schema``       — arguments validated against the tool contract
4. ``resource_constraint`` — **resource-aware authorization**
5. ``canary_exfil``     — exact-match canary in an argument
6. ``content_rule``     — OPTIONAL heuristic patterns, only if opted in
7. ``rate_limit`` / ``budget``
8. ``escalate``         — the seam to a host **semantic tier**; DENY with none wired
9. ``requires_confirmation``

Step 8 sits where it does for two reasons. It is last of the machine checks because
reaching a semantic tier is a model call, and nothing should pay for one on behalf of
a caller the cheap deterministic chain already refuses. It is *before* confirmation
because a human is the last word: a tool declaring both would otherwise have its
escalation skipped the moment an approval arrived.

The engine reads only the :class:`~histos.contracts.GateRequest` and the
static :class:`~histos.contracts.Policy` — never conversation, documents, or
prior outputs. Resource attributes come from a **trusted,
developer-provided** resolver, never from model output.
"""

from __future__ import annotations

import copy
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from histos import canary, detectors
from histos.content_rules import ContentRules
from histos.contracts import Effect, GateDecision, GateRequest, Policy
from histos.errors import ResourceNotFound
from histos.limits import LimitStore
from histos.schema import sensitive_fields, validate

# A resolver may be sync or async — looking a resource's real owner up is usually
# IO. The async form is only awaited on the async path (``apre``); handing one to a
# sync tool is a wiring error and fails closed rather than comparing a coroutine.
ResourceResolver = Callable[[str, dict[str, Any]], dict[str, Any] | Awaitable[dict[str, Any]]]

# The **semantic tier** a host wires behind a policy's ``escalate``: given the request,
# say whether meaning-level judgement lets it continue. Sync or async, like the
# resolver, because reaching one is usually a model call. A truthy return is the only
# outcome that continues the chain — and continuing is all it can do. There is no
# verdict here that allows something the deterministic chain refused, which is the
# property that keeps a probabilistic tier from ever widening a deterministic gate.
EscalationTier = Callable[[GateRequest], Any]

# "the resource was not fetched yet" — distinct from a resolver that legitimately
# returned an empty dict.
_UNRESOLVED: Any = object()


def _stringify(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _callback_args(args: dict[str, Any]) -> dict[str, Any]:
    """The argument view a host callback gets — a copy, never the live dict.

    ``confirm`` used to receive the very dict the gate then splats into the tool, so a
    well-meant normalisation in an approvals UI (rounding an amount, defaulting a
    field) landed in the executed call *after* every check had passed, and the audit
    record digested the mutated values. The semantic tier is handed the same request
    and is a far more likely place for a callback to rewrite what it was given.

    ``resource_resolver`` gets the same treatment, and it is the worst of the three to
    leave live: it runs *after* argument validation, so anything it writes into the
    dict reaches the tool having been checked against nothing. A resolver is ordinary
    application code — an ORM lookup, a cache fill — and normalising an id in passing
    is exactly the sort of thing it does.
    """
    try:
        return copy.deepcopy(args)
    except Exception:  # noqa: BLE001 — an uncopyable argument must not fail the call
        return dict(args)


# How far up a `raise ... from ...` chain the scan walks. Deep enough for any real
# wrapping (a driver error wrapped by an ORM wrapped by a repository), bounded because
# `__context__` can be made to cycle.
_MAX_EXCEPTION_CHAIN = 16


def _exception_text(exc: BaseException) -> str:
    """Everything a caller can read off a raised exception, as one string to scan.

    ``f"{type(exc).__name__}: {exc}"`` covers only the outermost message, and that is
    not where the secret usually is. A tool that catches a driver error and re-raises
    its own leaves the original on ``__cause__`` (explicit ``raise ... from``) or
    ``__context__` (an exception raised while handling another) — and Python prints
    the whole chain, so `psycopg.OperationalError: password authentication failed for
    user "svc:hunter2"` reached the model under a tidy ``RepositoryError`` that had
    been scanned and passed. ``__notes__`` is the same story with less ceremony: it is
    appended to the displayed traceback verbatim.

    Scanned together, in one string, because the decision is binary — either something
    had to be removed from what the caller can see, or nothing did — and the caller
    gets :class:`~histos.errors.ToolErrorRedacted`, which carries no chain of its own.
    """
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(_MAX_EXCEPTION_CHAIN):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        parts.append(f"{type(current).__name__}: {current}")
        notes = getattr(current, "__notes__", None)
        if isinstance(notes, list):
            parts.extend(str(note) for note in notes)
        # `__cause__` first: an explicit `raise X from Y` is the one the author meant.
        current = current.__cause__ or current.__context__
    return "\n".join(parts)


def for_callback(req: GateRequest) -> GateRequest:
    """The request a host callback sees: same identity, a detached copy of the args."""
    return GateRequest(req.tool_name, _callback_args(req.args), req.principal, phase=req.phase)


# The canary/secret scan is linear in the argument text, and `Field` has no cap on how
# many elements an array may carry — so one schema-valid call could hand the gate tens
# of megabytes and stall the calling thread (6.7 s measured for 20k max-length strings)
# inside a control that is supposed to be microsecond-scale. The blob is therefore
# budgeted, and a call that exceeds the budget is DENIED rather than scanned partially:
# truncating the text would silently stop looking for canaries past the cut, which is
# exactly the fail-open this gate must not have.
_MAX_SCAN_CHARS = 1_048_576


def _stringify_args(args: dict[str, Any]) -> tuple[str, bool]:
    """The text the pre-gate scans, plus whether the size budget was blown.

    Containers are walked leaf by leaf so the budget can stop an oversized argument
    *before* its text is materialised — ``str()`` on a 20k-element list costs the very
    megabytes the bound exists to avoid.
    """
    pieces: list[str] = []
    total = 0

    def walk(value: Any) -> bool:
        nonlocal total
        if isinstance(value, (list, tuple, set, frozenset)):
            return all(walk(v) for v in value)
        if isinstance(value, dict):
            return all(walk(k) and walk(v) for k, v in value.items())
        text = _stringify(value)
        total += len(text)
        if total > _MAX_SCAN_CHARS:
            return False
        pieces.append(text)
        return True

    for v in args.values():
        if not walk(v):
            return "", True
    return " ".join(pieces), False


# The output-side twin of `_MAX_SCAN_CHARS`. Generous — a real tool result is orders of
# magnitude smaller — because exceeding it costs the caller their result.
_MAX_OUTPUT_SCAN_CHARS = 4_194_304


def _text_blob(obj: Any) -> tuple[str, bool]:
    """Join every str/bytes leaf of ``obj``, the way the pre-gate joins arguments.

    Only *textual* leaves take part: calling ``str()`` on an arbitrary returned object
    would run user code inside the post-gate, and a ``__str__`` that raises would turn
    a call that already executed into a denial — the same shape as the NamedTuple bug
    :func:`_rebuild_container` exists to prevent.

    Dict *keys* are skipped: this blob exists to see a token split across adjacent
    values, and splicing a field name between two of them breaks exactly the adjacency
    it is looking for. Keys are still matched in both tiers leaf by leaf.

    Budgeted, and the budget is reported rather than silently applied. Tool output is
    attacker-controlled — that is the whole premise of the outbound half — so a tool
    that can be made to return tens of megabytes turns each call into hundreds of
    milliseconds of scanning and several times that in resident memory, inside a
    control advertised as microsecond-scale. Unlike the pre-gate, refusing outright is
    not available: the tool has already run. So the caller is told the blob was cut and
    decides; :meth:`Engine._post` treats a cut as a redact-all rather than scanning part
    of the output and reporting `allow`, which is the fail-open this must not have.
    """
    pieces: list[str] = []
    total = 0
    truncated = False

    def walk(value: Any) -> None:
        nonlocal total, truncated
        if truncated:
            return
        if isinstance(value, (str, bytes)):
            text = value if isinstance(value, str) else value.decode("utf-8", "surrogateescape")
            if total + len(text) > _MAX_OUTPUT_SCAN_CHARS:
                truncated = True
                return
            total += len(text)
            pieces.append(text)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for v in value:
                walk(v)

    walk(obj)
    return " ".join(pieces), truncated


def _with_ordinal(key: Any, n: int) -> Any:
    return key + f"#{n}".encode() if isinstance(key, bytes) else f"{key}#{n}"


def _put_redacted_key(out: dict[Any, Any], key: Any, value: Any) -> None:
    """Insert a key that redaction may have rewritten, without dropping a record.

    Two distinct secrets used as dict keys both redact to the same mark, so a plain
    assignment collapses two records into one — silent data loss in the middle of a
    security control, and invisible in the audit trail. Colliding redacted keys get an
    ordinal suffix instead. Every key goes through here, including untouched ones: a
    redacted key can also collide with a *literal* key that already spells the mark,
    and it was the untouched one that overwrote the record.
    """
    if key in out:
        n = 2
        while _with_ordinal(key, n) in out:
            n += 1
        key = _with_ordinal(key, n)
    out[key] = value


def _rebuild_container(obj: Any, items: list[Any]) -> Any:
    """Rebuild a sequence/set container of the same type from redacted ``items``.

    ``type(obj)(items)`` is wrong for a NamedTuple — its constructor takes positional
    fields, so redacting a NamedTuple return raised TypeError, which the post-gate
    turned into a fail-closed DENY *after* the tool had already run: the side effect
    happened and the caller got a denial. A tuple subclass that cannot be rebuilt at all
    degrades to a plain tuple; losing the type is acceptable, losing the redaction (or
    the call) is not.
    """
    make = getattr(obj, "_make", None)  # NamedTuple
    if isinstance(obj, tuple) and callable(make):
        try:
            return make(items)
        except (TypeError, ValueError):
            return tuple(items)
    try:
        return type(obj)(items)
    except (TypeError, ValueError):
        if isinstance(obj, list):
            return list(items)
        if isinstance(obj, frozenset):
            return frozenset(items)
        if isinstance(obj, set):
            return set(items)
        return tuple(items)


def _redact_structure(obj: Any, tokens: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively replace canary tokens in strings within ``obj``.

    Traverses str, bytes, dict (keys *and* values), list, tuple, set and
    frozenset, matching verbatim *and* normalized — the same two tiers the pre-gate
    applies, so the output channel is not the cheap way around the control.
    **Residual (honest):** it cannot reach into opaque objects (dataclass/Pydantic
    attributes, custom __str__), so a canary hidden inside such an object's fields is
    not redacted — canary is a mechanical, structural control, not a general
    exfiltration guard (see SECURITY.md).
    """
    found: list[str] = []
    if isinstance(obj, str):
        out_s, found = canary.redact(obj, tokens)
        out_s, norm_hits = canary.redact_normalized(out_s, tokens)
        found.extend(tok for tok in norm_hits if tok not in found)
        return out_s, found
    if isinstance(obj, bytes):
        out_b = obj
        for tok in sorted(tokens, key=len, reverse=True):  # longer first (see canary.redact)
            tb = tok.encode("utf-8", "ignore")
            if tb and tb in out_b:
                found.append(tok)
                out_b = out_b.replace(tb, b"[REDACTED-CANARY]")
        # surrogateescape round-trips any byte string exactly, so normalized matching
        # can run on text without disturbing a single byte outside a hit.
        text, norm_hits = canary.redact_normalized(out_b.decode("utf-8", "surrogateescape"), tokens)
        if norm_hits:
            found.extend(tok for tok in norm_hits if tok not in found)
            out_b = text.encode("utf-8", "surrogateescape")
        return out_b, found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k, khits = _redact_structure(k, tokens)
            new_v, vhits = _redact_structure(v, tokens)
            _put_redacted_key(out, new_k, new_v)
            found.extend(khits)
            found.extend(vhits)
        return out, found
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = []
        for v in obj:
            new_v, hits = _redact_structure(v, tokens)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found


def _validate_output(schema: Any, out: Any) -> list[str]:
    """Validate a tool output against its declared return schema.

    A dict is validated directly; a list/tuple is validated element-by-element
    (each must be an object); anything else is an unknown structure and fails.
    """
    if isinstance(out, dict):
        return validate(schema, out)
    if isinstance(out, (list, tuple)):
        errors: list[str] = []
        for i, item in enumerate(out):
            if isinstance(item, dict):
                errors.extend(f"[{i}] {e}" for e in validate(schema, item))
            else:
                errors.append(f"[{i}] is not an object")
        return errors
    return ["output is not an object or list of objects"]


def _redact_sensitive(obj: Any, sensitive_names: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively redact any dict key in ``sensitive_names`` — anywhere in ``obj``.

    Applies to nested structures and to *lists of records* (a common tool return),
    which the earlier top-level-dict-only check silently leaked. Redaction is by
    field *name* anywhere in the structure (conservative: over-redacts a same-named
    field rather than leak a sensitive one).
    """
    found: list[str] = []
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if k in sensitive_names:
                out[k] = "[REDACTED]"
                found.append(str(k))
            else:
                out[k], hits = _redact_sensitive(v, sensitive_names)
                found.extend(hits)
        return out, found
    if isinstance(obj, (list, tuple)):
        items = []
        for v in obj:
            new_v, hits = _redact_sensitive(v, sensitive_names)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found


def _project_output(obj: Any, allowed: frozenset[str]) -> tuple[Any, list[str]]:
    """Deny-by-default on the OUTPUT surface: drop any dict key not in ``allowed``.

    The surgical alternative to strict_returns' all-or-nothing — an undeclared field
    (where a secret can hide, out of reach of name-based redaction) simply never
    egresses. Recurses into nested objects and lists-of-records.
    """
    dropped: list[str] = []

    def go(o: Any) -> Any:
        if isinstance(o, dict):
            kept: dict[Any, Any] = {}
            for k, v in o.items():
                if k in allowed:
                    kept[k] = go(v)
                else:
                    dropped.append(str(k))
            return kept
        if isinstance(o, (list, tuple)):
            return _rebuild_container(o, [go(x) for x in o])
        return o

    return go(obj), dropped


def _redact_secrets_structure(obj: Any) -> tuple[Any, list[str]]:
    """Redact recognised secrets (checksum + structural) in every string leaf.

    Traverses exactly what the canary traverser does — str, bytes, dict keys *and*
    values, list, tuple, set, frozenset. It used to skip dict keys and bytes entirely,
    so a key→credential map (an AWS key listing) or any tool returning bytes (an HTTP
    body, a file read) handed the model the credential in the clear, with nothing in
    the audit trail: a leak the operator could not even see.
    """
    found: list[str] = []
    if isinstance(obj, str):
        red, kinds = detectors.redact_string(obj)
        found.extend(kinds)
        return red, found
    if isinstance(obj, bytes):
        # surrogateescape round-trips every byte, so only the detected span changes.
        red, kinds = detectors.redact_string(obj.decode("utf-8", "surrogateescape"))
        if not kinds:
            return obj, found
        found.extend(kinds)
        return red.encode("utf-8", "surrogateescape"), found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k, khits = _redact_secrets_structure(k)
            new_v, vhits = _redact_secrets_structure(v)
            _put_redacted_key(out, new_k, new_v)
            found.extend(khits)
            found.extend(vhits)
        return out, found
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = []
        for v in obj:
            new_v, hits = _redact_secrets_structure(v)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found


class Engine:
    def __init__(
        self,
        policy: Policy,
        limits: LimitStore,
        *,
        content_rules: ContentRules | None = None,
        resource_resolver: ResourceResolver | None = None,
        escalate: EscalationTier | None = None,
    ) -> None:
        self.policy = policy
        self.limits = limits
        self.content_rules = content_rules
        self.resource_resolver = resource_resolver
        self.escalate = escalate

    # ── pre-gate ─────────────────────────────────────────────────────

    def pre(self, req: GateRequest) -> GateDecision:
        """Decide a call synchronously; a resource constraint resolves inline."""
        try:
            return self._pre(req, _UNRESOLVED)
        except Exception as exc:  # noqa: BLE001 — fail-closed is the whole point
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}")

    async def apre(self, req: GateRequest) -> GateDecision:
        """Same decision *and the same side effects*, awaiting an async ``resource_resolver``.

        Only the resolver hop is async — evaluation itself stays synchronous and
        CPU-only, so the two paths cannot drift into different verdicts. The cheap
        checks (steps 1–3) run **before** the resolver on both paths: this path used to
        resolve first, so an unauthorized caller, or one whose arguments the schema
        rejects, still drove a real lookup in the host's trusted datastore — an
        existence/timing oracle and an SSRF primitive the sync path denied outright.
        """
        try:
            contract = self.policy.contract_for(req.tool_name)
            early = self._pre_before_resource(req, contract)
            if early is not None:
                return early
            resource: Any = _UNRESOLVED
            if contract is not None and contract.constraints and contract.needs_resource_resolver():
                if self.resource_resolver is None:
                    return self._no_resolver_decision(req.tool_name)
                try:
                    resolved = self.resource_resolver(req.tool_name, _callback_args(req.args))
                    if inspect.isawaitable(resolved):
                        resolved = await resolved
                except ResourceNotFound as exc:
                    return GateDecision(Effect.DENY, "resource_not_found", f"resource not found: {exc}")
                except Exception as exc:  # noqa: BLE001 — a raising resolver fails closed
                    return GateDecision(Effect.DENY, "resolver_error", f"resource_resolver raised: {exc!r}")
                resource = resolved or {}
            return await self._apre_after_resource(req, contract, resource)
        except Exception as exc:  # noqa: BLE001 — fail-closed
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}")

    @staticmethod
    def _no_resolver_decision(tool_name: str) -> GateDecision:
        return GateDecision(
            Effect.DENY,
            "no_resource_resolver",
            f"tool {tool_name!r} has resource constraints but no resource_resolver is configured",
        )

    def _pre(self, req: GateRequest, resource: Any = _UNRESOLVED) -> GateDecision:
        contract = self.policy.contract_for(req.tool_name)
        early = self._pre_before_resource(req, contract)
        if early is not None:
            return early
        return self._pre_after_resource(req, contract, resource)

    def _pre_before_resource(self, req: GateRequest, contract: Any) -> GateDecision | None:
        """Steps 1–3: the CPU-only checks that must precede any resolver side effect.

        Returns None when the call has earned a resource lookup — and only then, which
        is what keeps `pre` and `apre` identical in *what they touch*, not just in what
        they answer.
        """
        # 1. Deny-by-default: a tool with no contract is not gated → refused.
        if contract is None:
            return GateDecision(Effect.DENY, "unknown_tool", f"no policy for tool {req.tool_name!r}")

        # 2. RBAC allow-list (deny-by-default per role).
        if req.tool_name not in self.policy.allowed_tools(req.principal.role):
            return GateDecision(
                Effect.DENY,
                "rbac",
                f"role {req.principal.role!r} may not call {req.tool_name!r}",
                field="role",
                expected=f"grant for {req.tool_name!r}",
                received=req.principal.role,
            )

        # 3. Argument schema. A gated tool with no schema cannot be validated →
        #    fail closed, never wave the call through.
        if contract.args is None:
            return GateDecision(
                Effect.DENY, "no_arg_schema", f"tool {req.tool_name!r} has no arg schema; cannot gate safely"
            )
        errors = validate(contract.args, req.args)
        if errors:
            first = errors[0]
            field = first.split(":", 1)[0]
            return GateDecision(Effect.DENY, "arg_schema", "; ".join(errors), field=field)
        return None

    def _pre_after_resource(self, req: GateRequest, contract: Any, resource: Any = _UNRESOLVED) -> GateDecision:
        """Steps 4–9, resolving a sync semantic tier inline."""
        blocked = self._pre_checks(req, contract, resource)
        if blocked is not None:
            return blocked
        if not contract.requires_escalation:
            return self._chain_end(req, contract)
        refusal = self._escalate(req)
        return refusal if refusal is not None else self._after_escalation(req, contract)

    async def _apre_after_resource(self, req: GateRequest, contract: Any, resource: Any) -> GateDecision:
        """The same tail, awaiting an async semantic tier.

        The two paths are duplicated for exactly one hop, the same way the resolver is:
        everything that decides is in ``_pre_checks`` / ``_chain_end`` / a shared
        verdict reader, so the sync and async gates cannot drift into different
        verdicts — only into different ways of waiting for the same answer.
        """
        blocked = self._pre_checks(req, contract, resource)
        if blocked is not None:
            return blocked
        if not contract.requires_escalation:
            return self._chain_end(req, contract)
        refusal = await self._aescalate(req)
        return refusal if refusal is not None else self._after_escalation(req, contract)

    def _pre_checks(self, req: GateRequest, contract: Any, resource: Any = _UNRESOLVED) -> GateDecision | None:
        """Steps 4–7: every remaining check that is CPU-only. None = keep going.

        Split out so the sync and async paths share it verbatim, and so the two steps
        that can reach *outside* the process — the semantic tier, and the human behind
        confirmation — sit after every check that cannot.
        """
        # 4. Resource-aware authorization. Compares call/resource
        #    attributes against trusted principal context or literals.
        constraint_decision = self._check_constraints(req, contract, resource)
        if constraint_decision is not None:
            return constraint_decision

        # 5. Canary exfiltration attempt via an argument (verbatim + normalized).
        blob, oversized = _stringify_args(req.args)
        if oversized:
            # Arguments too large to scan are refused, not scanned in part: the canary
            # and secret checks below are only meaningful over the WHOLE argument text.
            return GateDecision(
                Effect.DENY,
                "arg_schema",
                f"arguments exceed the {_MAX_SCAN_CHARS} character budget the gate will scan",
                field=next(iter(req.args), ""),
                expected=f"<= {_MAX_SCAN_CHARS} characters of argument text",
                received="oversized",
            )
        if self.policy.canaries and (
            canary.find(blob, self.policy.canaries) or canary.find_normalized(blob, self.policy.canaries)
        ):
            return GateDecision(Effect.DENY, "canary_exfil", "argument contains a canary token")

        # 5b. A recognised secret in an argument — a checksum-confidence match denies;
        #     a structural-only match stays advisory (redacted on output, not a hard deny).
        if contract.deny_secret_args:
            for det in detectors.scan_string(blob):
                if det.confidence == detectors.CHECKSUM:
                    return GateDecision(
                        Effect.DENY,
                        "secret_detected",
                        f"argument contains a {det.kind} secret",
                        expected="no secret",
                        received=det.kind,
                    )

        # 6. OPTIONAL heuristic content rules, only if the host opted in.
        if self.content_rules is not None:
            hit = self.content_rules.scan(blob)
            if hit is not None:
                rule, _pattern = hit
                return GateDecision(Effect.DENY, rule, f"argument matched {rule}")

        # 7. Rate / budget limits (checked here, consumed later by the wrapper).
        limit_rule = self.limits.check(
            req.principal.identity, req.tool_name, rate_limit=contract.rate_limit, budget=contract.budget
        )
        if limit_rule is not None:
            # See `Gate._consume_limit`: the window is not in the policy format, so the
            # decision names it rather than leaving the reader of `rate_limit: 3` to guess.
            window = f" (window: {self.limits.window_seconds:g}s)" if limit_rule == "rate_limit" else ""
            return GateDecision(Effect.DENY, limit_rule, f"{limit_rule} exceeded for {req.tool_name!r}{window}")

        return None

    # ── the semantic seam (step 8) ───────────────────────────────────

    def _escalate(self, req: GateRequest) -> GateDecision | None:
        """Consult the semantic tier. ``None`` means it let the call continue.

        Every other outcome ends the call, **including having no tier at all**. That is
        the whole property: the seam has no verdict meaning "allow more than the
        deterministic chain already allowed", so wiring meaning in can never widen the
        gate, and leaving it out can never open one. There is deliberately no
        configuration — no ``on_missing``, no default callback, no mode — that turns the
        absence of a tier into an allow; the branch simply does not exist.
        """
        if self.escalate is None:
            return self._no_tier_decision(req.tool_name)
        try:
            verdict = self.escalate(for_callback(req))
        except Exception as exc:  # noqa: BLE001 — a raising tier fails closed
            return self._tier_error(f"escalate callback raised: {exc!r}")
        if inspect.isawaitable(verdict):
            # An async tier on the sync path: a coroutine object is truthy, so treating
            # it as a verdict would let every escalated call through un-judged — the one
            # mistake this seam exists to make impossible.
            closer = getattr(verdict, "close", None)
            if callable(closer):
                closer()
            return self._tier_error(
                f"escalate callback for {req.tool_name!r} is async but the tool is sync — "
                "an async tier can only be awaited on the async path"
            )
        return self._read_verdict(req, verdict)

    async def _aescalate(self, req: GateRequest) -> GateDecision | None:
        """:meth:`_escalate` with the one hop awaited. Same verdicts, same collapse."""
        if self.escalate is None:
            return self._no_tier_decision(req.tool_name)
        try:
            verdict = self.escalate(for_callback(req))
            if inspect.isawaitable(verdict):
                verdict = await verdict
        except Exception as exc:  # noqa: BLE001 — a raising tier fails closed
            return self._tier_error(f"escalate callback raised: {exc!r}")
        return self._read_verdict(req, verdict)

    @staticmethod
    def _read_verdict(req: GateRequest, verdict: Any) -> GateDecision | None:
        """Truthy continues the chain; anything else refuses. Shared by both paths."""
        if verdict:
            return None
        return GateDecision(
            Effect.DENY,
            "escalation_denied",
            f"the semantic tier refused {req.tool_name!r}",
            escalate=True,
        )

    @staticmethod
    def _no_tier_decision(tool_name: str) -> GateDecision:
        return GateDecision(
            Effect.DENY,
            "no_escalation_tier",
            f"tool {tool_name!r} must be escalated to a semantic tier but none is wired",
            expected="a semantic tier passed as Gate(escalate=...)",
            received="<none>",
            escalate=True,
        )

    @staticmethod
    def _tier_error(reason: str) -> GateDecision:
        return GateDecision(Effect.DENY, "escalation_error", reason, escalate=True)

    def _after_escalation(self, req: GateRequest, contract: Any) -> GateDecision:
        """The chain resumed once the tier let the call through.

        Never a bare ALLOW that skips step 9: a tool declaring both ``escalate`` and
        ``confirmation`` still has to reach the human, and the tier's approval is
        recorded on that decision rather than substituted for it.
        """
        decision = self._chain_end(req, contract)
        if decision.effect is Effect.ALLOW:
            return GateDecision(
                Effect.ALLOW,
                "escalated",
                f"the semantic tier approved {req.tool_name!r}",
                escalate=True,
            )
        return replace(decision, escalate=True)

    def _chain_end(self, req: GateRequest, contract: Any) -> GateDecision:
        """Step 9, and the ALLOW that ends the pre-gate."""
        if contract.requires_confirmation:
            return self._confirmation_decision(req, contract)
        return GateDecision(Effect.ALLOW, "allow")

    @staticmethod
    def _confirmation_decision(req: GateRequest, contract: Any) -> GateDecision:
        """The REQUIRE_CONFIRMATION decision, carrying the declared approval window.

        ``confirmation.expires_in`` is read defensively (``getattr``) because the field
        is part of the policy *format* and an engine must not break on a contract object
        that predates it. A window the engine cannot honour — zero, negative, or not an
        integer — is refused rather than downgraded to "no expiry": an approval that can
        never be inside its window must not be treated as one that never leaves it.

        The window itself is published on the decision so the host's approval store can
        enforce the clock (the engine has no clock and never consumes approvals); see
        the handoff in ``histos.approvals``.
        """
        window = getattr(contract, "confirmation_expires_in", None)
        if window is None:
            return GateDecision(
                Effect.REQUIRE_CONFIRMATION, "requires_confirmation", f"{req.tool_name!r} requires confirmation"
            )
        if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
            return GateDecision(
                Effect.DENY,
                "confirm_error",
                f"tool {req.tool_name!r} declares an unusable confirmation window ({window!r}); "
                "no approval could ever be valid",
                field="confirmation.expires_in",
                expected="a positive number of seconds",
                received=repr(window),
            )
        return GateDecision(
            Effect.REQUIRE_CONFIRMATION,
            "requires_confirmation",
            f"{req.tool_name!r} requires confirmation",
            expected=f"an approval granted within {window}s",
        )

    def _check_constraints(self, req: GateRequest, contract: Any, prefetched: Any = _UNRESOLVED) -> GateDecision | None:
        if not contract.constraints:
            return None

        resource: dict[str, Any] = {} if prefetched is _UNRESOLVED else prefetched
        if prefetched is _UNRESOLVED and contract.needs_resource_resolver():
            if self.resource_resolver is None:
                return self._no_resolver_decision(req.tool_name)
            try:
                resolved = self.resource_resolver(req.tool_name, _callback_args(req.args))
            except ResourceNotFound as exc:
                return GateDecision(Effect.DENY, "resource_not_found", f"resource not found: {exc}")
            except Exception as exc:  # noqa: BLE001 — a raising resolver fails closed, distinct from internal_error
                return GateDecision(Effect.DENY, "resolver_error", f"resource_resolver raised: {exc!r}")
            if inspect.isawaitable(resolved):
                # An async resolver on the sync path: comparing a coroutine to a
                # principal attribute would "fail" for the wrong reason. Close it so
                # Python does not warn about a never-awaited coroutine, and say why.
                closer = getattr(resolved, "close", None)
                if callable(closer):
                    closer()
                return GateDecision(
                    Effect.DENY,
                    "resolver_error",
                    f"resource_resolver for {req.tool_name!r} is async but the tool is sync — "
                    "an async resolver can only be awaited on the async path",
                )
            resource = resolved or {}

        for c in contract.constraints:
            result = c.evaluate(resource, req.principal)
            if not result.ok:
                return GateDecision(
                    Effect.DENY,
                    "resource_constraint",
                    result.reason,
                    field=result.field,
                    expected=result.expected,
                    received=result.received,
                )
        return None

    # ── post-gate ────────────────────────────────────────────────────

    def post(self, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
        try:
            return self._post(req, result)
        except Exception as exc:  # noqa: BLE001 — fail-closed
            return GateDecision(Effect.DENY, "internal_error", f"fail-closed on exception: {exc!r}"), None

    def post_exception(self, req: GateRequest, exc: BaseException) -> tuple[GateDecision, str]:
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
            return self._post_exception(req, exc)
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

    def _post_exception(self, req: GateRequest, exc: BaseException) -> tuple[GateDecision, str]:
        contract = self.policy.contract_for(req.tool_name)
        text = _exception_text(exc)
        redactions: list[str] = []

        if contract is not None and contract.scan_output_for_canary and self.policy.canaries:
            text, found = _redact_structure(text, self.policy.canaries)
            redactions.extend(f"canary:{tok}" for tok in found)

        if contract is not None and contract.redact_secret_output:
            text, kinds = detectors.redact_string(text)
            redactions.extend(f"secret:{k}" for k in dict.fromkeys(kinds))

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

    def _post(self, req: GateRequest, result: Any) -> tuple[GateDecision, Any]:
        contract = self.policy.contract_for(req.tool_name)
        redactions: list[str] = []
        out = result

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
            if not isinstance(out, (dict, list, tuple)):
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
            out, dropped = _project_output(out, frozenset(contract.returns.fields))
            redactions.extend(f"drop:{k}" for k in dict.fromkeys(dropped))

        # 1. Canary leak in the output → redact verbatim *and* normalized tokens
        #    anywhere in the structure, then ask the pre-gate's question of the whole
        #    thing: the pre-gate scans one blob joined from every argument, so it denies
        #    a token split across two of them, while per-leaf redaction cannot see a
        #    token split across two fields of the return. Post has to match at least as
        #    hard as pre or the output channel is the cheap way round the control — and
        #    a split token cannot be located leaf by leaf, so the value is dropped whole
        #    rather than returned with a leak the redactor could see but not reach.
        if contract is not None and contract.scan_output_for_canary and self.policy.canaries:
            out, found = _redact_structure(out, self.policy.canaries)
            redactions.extend(f"canary:{tok}" for tok in found)
            blob, blob_truncated = _text_blob(out)
            if blob_truncated:
                # Scanning a prefix and reporting `allow` on the rest is exactly the
                # fail-open the pre-gate's budget refuses an input to avoid. The tool
                # has already run, so the honest answer is to keep the decision and
                # drop the value.
                return (
                    GateDecision(
                        Effect.REDACT,
                        "post_redaction",
                        "tool output exceeded the scan budget, so it could not be checked for a canary",
                        redactions=("output:redacted_all",),
                    ),
                    "[REDACTED: tool output exceeded the scan budget and was not inspected]",
                )
            crossing = canary.find_normalized(blob, self.policy.canaries)
            if crossing:
                redactions.extend(f"canary:{tok}" for tok in crossing)
                redactions.append("output:redacted_all")
                why = "a canary token spans several output fields and cannot be redacted in place"
                return (
                    GateDecision(
                        Effect.REDACT, "post_redaction", f"{why} — output dropped", redactions=tuple(redactions)
                    ),
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
