"""How much of a value the gate is willing to read before it refuses to look.

Split out of `engine.py`. Every pass the gate makes over an argument or a return is
linear in what it is given, `re` does not release the GIL, and the size of both is
chosen by whatever the model was persuaded to send — so each side carries a budget, and
going over it is a refusal rather than a partial scan. Truncating instead would mean
silently not looking for a canary past the cut, which is the fail-open the whole module
exists to avoid.

Nodes are counted as well as characters: a return of twenty million integers costs no
text at all and still has to be walked and rebuilt by the passes downstream.
"""

from __future__ import annotations

from typing import Any

from histos.decide.redaction import _record_fields


def _stringify(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


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


def _over_output_budget(obj: Any, budget: int) -> bool:
    """Whether ``obj`` is too large for the post-gate passes to walk.

    Stops at the first character over, so the check costs the size of the budget rather
    than the size of the payload — the point is to refuse before anything expensive
    walks it, not to measure exactly how oversized it was.

    Counts *nodes* as well as characters, because the passes it bounds walk and rebuild
    the whole structure and not only its text. Measuring textual leaves alone meant a
    return of twenty million integers cost zero budget and was reported under it, while
    the secret pass then traversed and reconstructed every one of them.
    """
    # The guard covers both walks. It used to sit inside `_node_count_over` only, and
    # `_text_blob` recurses over the same containers with none — so for a structure too
    # deep to walk, the stack blew in the *first* call, the RecursionError went past the
    # handler into `post()`'s catch-all, and the answer was `DENY / internal_error`
    # instead of the budget REDACT this exists to produce. `x = [1,2,3]; x.append(x)` is
    # the whole reproduction.
    try:
        _, truncated = _text_blob(obj, budget)
        return truncated or _node_count_over(obj, budget)
    except RecursionError:  # too deep to walk is too deep to scan
        return True


def _node_count_over(obj: Any, budget: int) -> bool:
    """Whether ``obj`` holds more values than the budget allows, stopping at the bound."""
    remaining = budget

    def walk(value: Any) -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            return True
        if isinstance(value, dict):
            return any(walk(k) or walk(v) for k, v in value.items())
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(walk(v) for v in value)
        # The same door the projector was given, and was not given here in the same
        # commit. A record was charged one node and zero characters however much it
        # wrapped, so the bound that exists to stop attacker-chosen output turning one
        # call into a stall reported it under budget — and then the projector walked
        # every field of it.
        fields = _record_fields(value)
        if fields is not None:
            return any(walk(v) for v in fields.values())
        return False

    try:
        return walk(obj)
    except RecursionError:  # too deep to walk is too deep to scan
        return True


def _text_blob(obj: Any, budget: int) -> tuple[str, bool]:
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
            if total + len(text) > budget:
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
        else:
            # Records too. `_project_output` was taught to enter them and this walk was
            # not, so the character half of the budget saw nothing inside one either.
            fields = _record_fields(value)
            if fields is not None:
                for v in fields.values():
                    walk(v)

    walk(obj)
    return " ".join(pieces), truncated
