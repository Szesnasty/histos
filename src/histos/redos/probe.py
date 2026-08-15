"""Measuring a pattern instead of predicting it.

Split out of `schema.py`. The structural screen reasons about shape and is therefore
wrong in both directions at the edges. This runs the compiled pattern against a ladder
of inputs built from its *own* alphabet — a pattern over `[b-d]` probed with `a`s matches
nothing and returns instantly, which is how a bomb once loaded clean — and refuses one
that spends more CPU than the budget allows.

The clock is the subtle part. `time.thread_time` is the right *quantity*, because `re`
holds the GIL for the whole backtrack, but on Windows it is `GetThreadTimes` with a
15.6 ms tick and every small rung reads zero. So the clock is chosen by measuring its
step size, not by asking `get_clock_info`, which reports a nominal resolution.
"""

from __future__ import annotations

import re

# The private modules on purpose: the alternative is a second regex parser, and a
# screen that disagrees with the engine it is protecting is worse than no screen.
import re._constants as _re_const
import re._parser as _re_parser
import time
from collections.abc import Callable
from typing import Any

from histos.errors import PolicyError
from histos.redos.alphabet import (
    _ALPHABET,
    _ATOMIC_REPEATS,
    _BACKTRACKING_REPEATS,
    _MAX_PATTERN_INPUT,
    _NON_ASCII_DIGIT,
    _NON_ASCII_OTHER,
    _NON_ASCII_SPACE,
    _NON_ASCII_WORD,
    _bucket,
    _class_codepoints,
    _variable_width,
)
from histos.redos.shapes import _backtracking_risk


# against synthetic worst cases — runs of one character ending in a byte that forces the
# match to fail and backtrack.
#
# The filler used to be the fixed list ("a", "0", " ", "aA0_.-"), which had nothing to do
# with the pattern in front of it: a pattern over `[b-d]` was probed with characters it
# can never match, matched nothing, returned instantly, and loaded. The exact same shape
# spelled with `\w` was caught, which is the whole tell. The filler now comes out of the
# pattern's own alphabet, and the terminator is chosen to be a character the pattern cannot
# match at all, so the probe reaches the backtracking rather than failing in front of it.
def _probe_clock() -> Callable[[], float]:
    """The clock the ladder measures rungs with: CPU where CPU can be read finely enough.

    CPU is the right quantity — `re` holds the GIL while it backtracks, so a wall clock
    on a loaded machine measures the other tenants and refused `ORD-[0-9]+` on a CI
    runner for it. But `thread_time` on Windows is `GetThreadTimes`, whose granularity is
    the ~15.6 ms system tick. Every small rung then reads exactly 0.0, the growth
    extrapolation that gates the next rung never fires, and the ladder climbs all the way
    to 4 KiB on a pattern it should have refused at 64 characters: a degree-12 pattern
    that costs 4 ms here cost **8.7 seconds** there, inside `Field.__post_init__`, once
    per tool in the manifest. A self-bounding probe that cannot see its own budget is not
    bounded at all.

    So the clock has to be able to resolve the budget. Where CPU cannot, elapsed time is
    the better of the two available answers, and the confirmation pass is what keeps a
    scheduling hiccup from becoming a refusal.
    """
    candidate = getattr(time, "thread_time", None)
    if candidate is not None and _granularity_under(candidate, _PROBE_BUDGET_S / 50):
        return candidate
    return time.perf_counter


def _granularity_under(clock: Callable[[], float], limit: float) -> bool:
    """Whether ``clock`` can actually resolve a duration of ``limit``, measured.

    Asked by spinning rather than by reading `time.get_clock_info`, which reports the
    clock's *nominal* resolution: Windows answers 100 ns for `thread_time` while
    `GetThreadTimes` only advances on the ~15.6 ms scheduler tick. Trusting that number
    is how the first version of this check passed on Windows and left the ladder
    climbing to 4 KiB on a pattern it should have refused at 64 characters.

    The *size* of the first step, not whether one happened. Asking only whether the
    clock moved inside the window was a race and behaved like one: Windows' 15.6 ms tick
    lands inside a 1 ms window about six times in a hundred, so the selection came out
    fine-grained on some runs and coarse on others, and CI went green and red on the
    same commit. A step of 15.6 ms answers the question whichever run observes it.

    Bounded by `limit`: a clock that has not moved in that long cannot resolve it
    either. Costs microseconds on a fine clock and one `limit` once at import on a
    coarse one.
    """
    started = clock()
    deadline = time.perf_counter() + limit
    while time.perf_counter() < deadline:
        step = clock() - started
        if step > 0:
            return step <= limit
    return False


_PROBE_BUDGET_S = 0.05
_cpu_clock: Callable[[], float] = _probe_clock()
# The ladder starts at 8, not at 64. Eight characters cannot be expensive for any pattern
# — that is the point of starting there — whereas 64 already is: a degree-8 pattern spends
# 45 s on its *first* probe at 64, so a ladder that starts there has nothing to measure
# before it is already hung. Starting small buys two cheap rungs to read the growth rate
# off before any rung can cost real time.
_PROBE_SIZES = (8, 16, 32, 64, 128, 256, 512, 1024, 2048, _MAX_PATTERN_INPUT)
# Four characters, so five probe strings. Enough to cover a pattern's repeats and the
# literals wedged between them; more than that and the probe set costs more than it finds.
_MAX_PROBE_CHARS = 4

# Which character to stand in for a set, most legible first. Any member would do; a
# deterministic choice keeps the probe reproducible from one load to the next.
_FILLER_PREFERENCE = tuple(
    dict.fromkeys(
        [ord(c) for c in "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-. "]
        + list(range(33, 127))
        + list(range(128))
    )
)
# One real character per non-ASCII bucket, for a pattern whose repeats are entirely
# outside ASCII — otherwise `[一-鿿]+` gets probed with nothing at all.
_BUCKET_SAMPLES = {
    _NON_ASCII_DIGIT: "٣",
    _NON_ASCII_WORD: "é",
    _NON_ASCII_SPACE: " ",
    _NON_ASCII_OTHER: "→",
}
# Terminators, tried in order until one lands outside everything the pattern can match.
# Newline first: it is the one character `.` refuses, and `\w`, `\d`, `[a-z]` and most
# negated classes refuse it too, so it is the terminator most patterns cannot swallow.
_TERMINATORS = ("\n", "!", "\x00", "\x01", "\U0010fffe")


def _contained_codepoints(seq: Any) -> frozenset[int]:
    """Every ``_ALPHABET`` member anywhere inside a subtree.

    Deliberately an over-approximation in both of its uses: too wide a set only picks a
    filler the pattern will not chew on, or drives the terminator down to the last
    fallback. Too narrow a one would pick a *terminator the pattern matches*, and then
    the probe never reaches the backtracking it exists to measure.
    """
    points: set[int] = set()
    for op, av in seq:
        if op is _re_const.LITERAL:
            points.add(_bucket(av))
        elif op is _re_const.NOT_LITERAL:
            points |= _ALPHABET - {_bucket(av)}
        elif op in (_re_const.ANY, _re_const.ANY_ALL):
            # `.` is counted as matching the newline it actually refuses, deliberately. Being
            # exact here would make `\n` the terminator for every pattern containing a `.`,
            # and probing `^[a-z]+.*$` with it costs 38 ms of the 50 ms budget — so the
            # ordinary log rules this screen was just taught to accept would start being
            # refused on any machine a third slower than this one. The cost is that a pattern
            # whose only forcing character is a newline *and* which contains a `.` is probed
            # with something it can swallow; the shape screen is what covers that case.
            points |= _ALPHABET
        elif op is _re_const.IN:
            known = _class_codepoints(av)
            points |= _ALPHABET if known is None else known
        elif op in _BACKTRACKING_REPEATS or op in _ATOMIC_REPEATS:
            points |= _contained_codepoints(av[2])
        elif op is _re_const.SUBPATTERN:
            points |= _contained_codepoints(av[3])
        elif op is _re_const.ATOMIC_GROUP:
            points |= _contained_codepoints(av)
        elif op is _re_const.BRANCH:
            for branch in av[1]:
                points |= _contained_codepoints(branch)
        elif op in (_re_const.ASSERT, _re_const.ASSERT_NOT):
            points |= _contained_codepoints(av[1])
        elif op is _re_const.GROUPREF_EXISTS:
            for branch in av[1:]:
                if branch:
                    points |= _contained_codepoints(branch)
    return frozenset(points)


def _sample(points: frozenset[int]) -> str:
    """One character out of a set of ``_ALPHABET`` members, or "" if there is none."""
    for codepoint in _FILLER_PREFERENCE:
        if codepoint in points:
            return chr(codepoint)
    for bucket, sample in _BUCKET_SAMPLES.items():
        if bucket in points:
            return sample
    return ""


def _probe_alphabets(seq: Any, found: list[tuple[bool, frozenset[int]]]) -> None:
    """Collect ``(drives backtracking, alphabet)`` for every atom, in source order.

    The variable repeats are the ones that can backtrack, so their characters are worth
    the most and go first. Everything else still has to be in the list, though: the run
    has to get *past* `x` and `[b-d]{3}` before the repeats around them can blow up, and
    a filler that cannot spell them fails in front of the interesting part and reports a
    fast pattern. That is the same mistake the fixed filler list made, one level in.
    """
    for op, av in seq:
        if op in _BACKTRACKING_REPEATS or op in _ATOMIC_REPEATS:
            found.append((_variable_width(av), _contained_codepoints(av[2])))
            _probe_alphabets(av[2], found)
        elif op is _re_const.LITERAL:
            found.append((False, frozenset({_bucket(av)})))
        elif op is _re_const.IN:
            known = _class_codepoints(av)
            found.append((False, _ALPHABET if known is None else known))
        elif op is _re_const.SUBPATTERN:
            _probe_alphabets(av[3], found)
        elif op is _re_const.ATOMIC_GROUP:
            _probe_alphabets(av, found)
        elif op is _re_const.BRANCH:
            for branch in av[1]:
                _probe_alphabets(branch, found)
        elif op in (_re_const.ASSERT, _re_const.ASSERT_NOT):
            _probe_alphabets(av[1], found)
        elif op is _re_const.GROUPREF_EXISTS:
            for branch in av[1:]:
                if branch:
                    _probe_alphabets(branch, found)


def _probe_inputs(parsed: Any) -> tuple[str, ...]:
    """Fillers to build probe strings from, drawn from the pattern's own alphabet."""
    atoms: list[tuple[bool, frozenset[int]]] = []
    _probe_alphabets(parsed, atoms)
    chars: list[str] = []
    for points in [p for drives, p in atoms if drives] + [p for drives, p in atoms if not drives]:
        char = _sample(points)
        if char and char not in chars:
            chars.append(char)
        if len(chars) == _MAX_PROBE_CHARS:
            break
    if not chars:
        return ("a",)
    # each character on its own, then all of them interleaved, because a boundary between
    # two repeats only backtracks when the run reaches across it.
    return (*chars, "".join(chars)) if len(chars) > 1 else (chars[0],)


def _probe_terminator(parsed: Any) -> str:
    """A character the pattern cannot match, so the probe ends in a forced failure."""
    matchable = _contained_codepoints(parsed)
    return next((t for t in _TERMINATORS if _bucket(ord(t)) not in matchable), _TERMINATORS[-1])


def _slow_pattern_error(pattern: str, elapsed: float, size: int) -> PolicyError:
    return PolicyError(
        f"pattern {pattern!r} spent {elapsed * 1000:.0f} ms of a {_PROBE_BUDGET_S * 1000:.0f} ms budget "
        f"to reject a {size}-character string, and an argument may be {_MAX_PATTERN_INPUT} characters — "
        "refusing it. `re` has no step budget and does not release the GIL, so the cost this pattern "
        "already shows at load would be paid, larger, inside the gate with the whole process stopped. "
        "Anchor it, bound its repeats with `{m,n}`, or make adjacent repeats match disjoint characters.",
        code="unsafe_pattern",
    )


def _reject_slow_pattern(pattern: str, compiled: re.Pattern[str], parsed: Any) -> None:
    """Refuse a pattern that is measurably slow on a synthetic worst case.

    A timing check is a blunt instrument, and this one only sees the worst cases it
    thinks to build — a pattern that is quadratic on some other input still gets
    through. It is here for the shapes the parse-tree screen structurally cannot see,
    not as a replacement for it.

    The budget used to be checked only *between* probes, which bounded nothing: the run
    that blew it was already running, and a pattern tuned to the probe spent 1.35 s of
    load time inside a 50 ms budget — 27x — with a hostile manifest free to multiply that
    by the number of tools it declares. So each size is now also gated on what the
    previous two cost: the ratio between them is the pattern's polynomial degree showing
    itself, and a degree that projects past the budget is refused instead of measured.
    Total load-time cost is bounded by roughly twice the budget rather than by nothing.
    """
    # Measured twice before it can refuse, because this is a clock and clocks lie about
    # a busy machine. The first run on a loaded CI runner refused `ORD-[0-9]+` — a
    # linear pattern with nothing wrong with it — because fifty descheduled `fullmatch`
    # calls added up to 50 ms of *wall* time while costing microseconds of CPU. A policy
    # that loads on one worker and not on another is not a security control, it is a
    # coin toss, and the direction it lands is an outage.
    #
    # So: the clock is `thread_time`, which counts only CPU this thread actually burned
    # and is exactly the quantity being bounded — `re` holds the GIL for it. And a
    # verdict is confirmed before it is acted on. A genuinely catastrophic pattern
    # exceeds the budget by orders of magnitude on every attempt; a scheduling hiccup
    # does not survive being asked again.
    verdict, decisive = _probe_once(pattern, compiled, parsed)
    if verdict is None or decisive:
        # A decisive verdict is one the clock cannot have invented: a *measured* overrun
        # several times the budget. Confirming those would double the load-time cost of
        # exactly the manifests this bound exists for — N tools of probe-tuned patterns
        # multiply whatever one probe costs — and buy nothing, because no scheduling
        # hiccup turns microseconds into four times the budget.
        if verdict is not None:
            raise verdict
        return
    # Marginal, or projected rather than measured. That is the shape a busy machine
    # produces, so it is asked again before it costs anyone a policy.
    confirmation, _ = _probe_once(pattern, compiled, parsed)
    if confirmation is not None:
        raise confirmation


# How far past the budget a measured run has to land before the clock stops being a
# plausible explanation for it.
_PROBE_DECISIVE = 4.0


def _probe_once(pattern: str, compiled: re.Pattern[str], parsed: Any) -> tuple[PolicyError | None, bool]:
    """One full ladder.

    Returns the error this run would raise (or None) and whether that verdict is
    decisive — measured, and far enough past the budget that no scheduling noise
    explains it. A verdict from the *projection* guard is never decisive: it is a
    prediction made from one sample, and one inflated sample is precisely what a loaded
    machine produces.
    """
    fillers = _probe_inputs(parsed)
    terminator = _probe_terminator(parsed)
    previous = before = 0.0  # slowest single probe at the last size, and the one before it
    elapsed = 0.0
    for size in _PROBE_SIZES:
        growth = max(2.0, previous / before) if before > 0 else 2.0
        if previous * growth * len(fillers) > _PROBE_BUDGET_S:
            return _slow_pattern_error(pattern, elapsed, size), False
        worst = 0.0
        for filler in fillers:
            probe = (filler * (size // len(filler) + 1))[: size - len(terminator)] + terminator
            started = _cpu_clock()
            compiled.fullmatch(probe)
            took = _cpu_clock() - started
            elapsed += took
            worst = max(worst, took)
            if elapsed > _PROBE_BUDGET_S:
                decisive = elapsed > _PROBE_DECISIVE * _PROBE_BUDGET_S
                return _slow_pattern_error(pattern, elapsed, size), decisive
        before, previous = previous, worst
    return None, True


def reject_catastrophic_backtracking(pattern: str, compiled: re.Pattern[str]) -> None:
    parsed = _re_parser.parse(pattern)
    risk = _backtracking_risk(parsed, in_repeat=False, at_tail=True)
    if risk is not None:
        raise PolicyError(
            f"pattern {pattern!r} can backtrack exponentially, or polynomially in a way 4 KiB of "
            f"input turns into hours — refusing it. It contains {risk}. "
            "`re` has no step budget and does not release the GIL, so one crafted argument would "
            "stall this process; the pattern is refused at load rather than at 4 KiB of input. "
            "Rewrite it with a character class, a bounded repeat `{m,n}`, or an atomic group `(?>...)`.",
            code="unsafe_pattern",
        )
    _reject_slow_pattern(pattern, compiled, parsed)
