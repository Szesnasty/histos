"""Reading everything a caller can see on a raised exception.

Split out of `engine.py`. A raised exception is the other way a tool hands content back
to the model, and it is the one that skipped redaction entirely for a long time: the
outermost message is not where the secret usually is. A chain is also a *tree* rather
than a line — `__cause__`, `__context__`, `__notes__`, and every member of an
`ExceptionGroup` — and each of those was, at some point, the branch nobody walked.

Bounded three ways, and the three are different questions: how deep a `raise ... from`
chain may go, how many exceptions may be visited in total (a fan-out reports one sibling
per failed task and forty is ordinary; forty *links* is a program that has lost track of
what it is re-raising), and how much text may be read.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from histos.decide.budget import _MAX_OUTPUT_SCAN_CHARS

# How far up a `raise ... from ...` chain the scan walks. Deep enough for any real
# wrapping (a driver error wrapped by an ORM wrapped by a repository), bounded because
# `__context__` can be made to cycle.
_MAX_EXCEPTION_CHAIN = 16

# How many exceptions the walk will visit in total, links and group members together.
# Separate from the depth bound above because a fan-out reports one sibling per failed
# task and forty of them is an ordinary Tuesday, while forty *links* is a program that
# has lost track of what it is re-raising. The real limiter on work is the character
# budget the walk already carries; this only stops a pathological structure.
_MAX_EXCEPTION_NODES = 1024


def _next_link(exc: BaseException) -> BaseException | None:
    """The next exception CPython would display — its rules, not an approximation.

    `__cause__ or __context__` is wrong twice. An exception class defining `__bool__`
    or `__len__` can be *falsy*, and `or` then skips a link `traceback` prints. And
    `raise X from None` sets `__suppress_context__`, which is the standard way to hide
    a driver error deliberately — walking into it made the gate redact an error that
    leaked nothing, swap the caller's exception type for `ToolErrorRedacted`, and put
    the suppressed context into the audit trail. What Python will not display is not
    something the caller can read.
    """
    if exc.__cause__ is not None:
        return exc.__cause__
    return None if exc.__suppress_context__ else exc.__context__


def _hidden_branches(exc: BaseException) -> list[BaseException]:
    """Every exception in the displayed chain that hides a `__context__` behind it.

    The compensating scan used to be applied to ``exc`` alone, and `_exception_text`
    stops dead at each `__suppress_context__` it meets — so the ordinary two-level shape
    was never inspected at all: a repository hides the driver error with
    ``raise Repo(...) from None``, a service wraps the repository with
    ``raise Service(...) from repo``, and the driver's secret is in neither the scanned
    text nor the depth-0 hidden scan, which sees only the service error.

    Walks the same links `_exception_text` walks, by the same rules, and reports the
    branches it had to step over rather than the text.
    """
    found: list[BaseException] = []
    seen: set[int] = set()
    pending: deque[BaseException] = deque([exc])
    while pending and len(seen) < _MAX_EXCEPTION_NODES:
        current = pending.popleft()
        if id(current) in seen:
            continue
        seen.add(id(current))
        hidden = current.__context__
        if current.__suppress_context__ and hidden is not None and hidden is not current.__cause__:
            found.append(current)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        link = _next_link(current)
        if link is not None:
            pending.append(link)
    return found


def _exception_text(exc: BaseException, budget: int | None = None) -> tuple[str, bool]:
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

    A chain is a tree, not a line. ``__cause__``/``__context__`` alone missed every
    member of an :class:`ExceptionGroup`, which is how ``asyncio.TaskGroup`` and every
    fan-out tool report partial failure: ``ExceptionGroup("2 of 3 shards failed", [...])``
    scanned as that one sentence, found nothing, and the gate re-raised the original
    group with both sub-exceptions — and their secrets — intact, while the identical
    payload on a ``raise ... from`` chain was caught. So the walk is breadth-first over
    links *and* members.

    Bounded by ``budget`` as well as by link count. The return path got a size budget
    because the scan is linear in the text and a manipulated model can make the text
    enormous; the raise path is the same channel and was left with none, so a chain of
    sixteen exceptions each carrying a megabyte of message was materialised in full and
    then NFKC-normalised and run past every detector. Tool error text is as
    attacker-controlled as tool output. Over budget returns ``incomplete``, which the
    caller already turns into a redact-all rather than a partial scan.
    """
    # Resolved here, not as a default argument: `_MAX_OUTPUT_SCAN_CHARS` is declared
    # further down the module, beside the input budget it is the twin of.
    budget = _MAX_OUTPUT_SCAN_CHARS if budget is None else budget
    parts: list[str] = []
    total = 0
    seen: set[int] = set()
    # Depth travels with each node, because breadth and depth are different questions
    # and one counter answered both. Members were pushed onto the same queue as links
    # and charged to the same sixteen, so `ExceptionGroup("3 of 40 shards failed", [...])`
    # — one link deep, which is the whole point of a group — ran the counter out on its
    # members and came back `incomplete`. The caller turns that into a redact-all, so an
    # ordinary `asyncio.TaskGroup` fan-out had its real error replaced by "the exception
    # chain is longer than 16 links". A group member is a sibling, not another link.
    pending: deque[tuple[BaseException, int]] = deque([(exc, 0)])
    nodes = 0

    def take(text: str) -> bool:
        """Append one piece, or refuse it and stop. Refused rather than appended, so an
        over-budget chain is never joined into the megabytes the budget exists to avoid
        touching — the caller drops the text whole when `incomplete` comes back true."""
        nonlocal total
        if total + len(text) > budget:
            return False
        parts.append(text)
        total += len(text)
        return True

    while pending:
        if nodes >= _MAX_EXCEPTION_NODES:
            break
        current, depth = pending.popleft()
        if id(current) in seen:
            continue
        seen.add(id(current))
        nodes += 1
        if not take(f"{type(current).__name__}: {current}"):
            return "\n".join(parts), True
        notes = getattr(current, "__notes__", None)
        # A Sequence, not a list: `add_note` builds a list, but the attribute is
        # writable and `traceback` prints whatever is iterable there. A `str` is a
        # Sequence too and would be printed one character per line, so it is excluded.
        # Anything else iterable-but-not-Sequence, or not iterable at all, is printed by
        # CPython as its `repr`, so that is what gets scanned rather than nothing.
        if isinstance(notes, Sequence) and not isinstance(notes, (str, bytes)):
            for note in notes:
                if not take(str(note)):
                    return "\n".join(parts), True
        elif notes is not None and not take(repr(notes)):
            return "\n".join(parts), True
        if isinstance(current, BaseExceptionGroup):
            # Siblings, at the group's own depth.
            pending.extend((member, depth) for member in current.exceptions)
        link = _next_link(current)
        if link is not None and depth + 1 < _MAX_EXCEPTION_CHAIN:
            pending.append((link, depth + 1))
        elif link is not None:
            return "\n".join(parts), True
    # A bound was hit with exceptions still to read. Saying "nothing to redact" about
    # a chain that was not read to the end is the fail-open this walk exists to close,
    # so the caller is told the text is incomplete and drops it whole.
    return "\n".join(parts), bool(pending)
