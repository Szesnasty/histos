"""A deliberately tiny, deterministic schema validator.

This is **not** a JSON-Schema engine. It is the minimal, dependency-free subset
needed to (a) validate tool *arguments* before execution and (b) describe a
tool's *return* shape so sensitive fields can be redacted after execution.
Everything here is pure and fail-closed by construction: an unrecognised type or
a validation error is reported, never silently accepted.

Kept intentionally small so policy evaluation stays microsecond-scale and easy to
reason about — a policy bug becomes an availability incident, so the evaluator
must stay simple enough to hold in your head.
"""

from __future__ import annotations

import math
import re
import re._constants as _re_const
import re._parser as _re_parser
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from histos.errors import PolicyError

# Cap the input a regex ever sees. This is a size bound and nothing more: at a
# backtracking degree of three or four, 4 KiB is not a bound at all — a merely
# *polynomial* pattern turns it into hours, and an exponential one into years. The
# time bound is `_reject_catastrophic_backtracking` below, which refuses such a
# pattern at policy-load time. Both apply; only the second one bounds time.
_MAX_PATTERN_INPUT = 4_096

# Largest magnitude a numeric bound may carry. Beyond this, `float()` on the value
# overflows and the comparison/`multiple_of` arithmetic in `_check_number` raises
# OverflowError *inside the gate* — an uncaught exception where a decision belongs.
_MAX_BOUND = 1e308

_TYPE_CHECKS: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": (list, tuple),
    "object": dict,
    "any": object,
}

# ── ReDoS screen ─────────────────────────────────────────────────────────
#
# A `pattern` reaching this module is untrusted: it may come from an MCP/OpenAPI
# server the user merely pointed at. `re` is a backtracking engine with no step
# budget and no timeout, and it does not release the GIL, so a catastrophic
# pattern cannot be interrupted by a watchdog thread once it starts — by the time
# a bad pattern is running it is already too late. The only fail-closed answer
# available without a new engine is to refuse the pattern *before* it can run.
#
# So the pattern is parsed with the stdlib's own parser and refused when its shape
# admits runaway backtracking. Four shapes cover the catastrophic families:
#
#   nested variable repeat   (a+)+           — 2ⁿ ways to split the input
#   alternation in a repeat  (a|ab)*         — same, via ambiguous branches
#   repeat of the same thing \d+\d+          — every split of the run has to be tried
#   overlapping neighbours   [a-z]+[a-z0-9]+ — likewise, once per shared character
#
# The last of those used to be allowed, on the theory that `_MAX_PATTERN_INPUT` bounded
# it. It does not: adjacency is a *degree*, not a constant. Three overlapping repeats in
# a row is O(n³) and four is O(n⁴), and the perfectly ordinary
# `^[A-Za-z0-9]+[A-Za-z0-9_-]+[A-Za-z0-9]+$` took 48 seconds on a single 4 KiB argument,
# with the GIL held for all of it. So neighbours are now compared by the *characters they
# can match* rather than by parse-tree equality: any overlap at all is refused, which
# still lets `\w+\s+\w+` — adjacent but disjoint, so unambiguous — load.
#
# Two repeats also count as neighbours across anything that can match empty, because
# `[a-z]+_?[a-z]+` is the quadratic pattern with a decoration in the middle.
#
# The screen is deliberately conservative: it rejects some patterns that happen to be
# safe (`(a|b)*`, which a character class expresses anyway). A false positive is a loud
# load-time error with a suggested rewrite; a false negative is a hung process holding
# the GIL. Atomic groups and possessive quantifiers cannot be backtracked into, so they
# reset the analysis rather than tripping it.
#
# Conservative is not the same as coarse, though, and the one relaxation below is there
# because being coarse cost real patterns: `.` intersects almost every class, so treating
# a trailing `.*`/`.+` as an overlap refused `^\w+.+$` and `^\s*[-*]\s+.+$` — log rules
# that cost 0.00 s on 4 KiB of anything. A screen that refuses honest input gets switched
# off, and a screen that is switched off catches nothing.
_BACKTRACKING_REPEATS = frozenset({_re_const.MAX_REPEAT, _re_const.MIN_REPEAT})
_ATOMIC_REPEATS = frozenset({_re_const.POSSESSIVE_REPEAT})

# The alphabet the overlap test reasons over. ASCII is carried exactly; everything above
# it collapses into four buckets, one per distinction `\d`/`\w`/`\s` and their negations
# can draw. Four buckets rather than one because collapsing the whole tail into a single
# "non-ASCII" atom would make `\d+\D+` — exact complements, and unambiguous — look like
# an overlap and refuse it.
_NON_ASCII_DIGIT = 0x110000
_NON_ASCII_WORD = 0x110001  # word, but not a digit
_NON_ASCII_SPACE = 0x110002
_NON_ASCII_OTHER = 0x110003
_NON_ASCII = frozenset({_NON_ASCII_DIGIT, _NON_ASCII_WORD, _NON_ASCII_SPACE, _NON_ASCII_OTHER})
_ALPHABET = frozenset(range(128)) | _NON_ASCII

_ASCII_DIGIT = frozenset(c for c in range(128) if chr(c).isdigit())
_ASCII_SPACE = frozenset(c for c in range(128) if chr(c).isspace())
_ASCII_WORD = frozenset(c for c in range(128) if chr(c).isalnum() or chr(c) == "_")

_CATEGORY_SETS: dict[Any, frozenset[int]] = {
    _re_const.CATEGORY_DIGIT: _ASCII_DIGIT | {_NON_ASCII_DIGIT},
    _re_const.CATEGORY_SPACE: _ASCII_SPACE | {_NON_ASCII_SPACE},
    _re_const.CATEGORY_WORD: _ASCII_WORD | {_NON_ASCII_DIGIT, _NON_ASCII_WORD},
}
_CATEGORY_SETS.update(
    {
        negated: _ALPHABET - _CATEGORY_SETS[positive]
        for positive, negated in (
            (_re_const.CATEGORY_DIGIT, _re_const.CATEGORY_NOT_DIGIT),
            (_re_const.CATEGORY_SPACE, _re_const.CATEGORY_NOT_SPACE),
            (_re_const.CATEGORY_WORD, _re_const.CATEGORY_NOT_WORD),
        )
    }
)


def _variable_width(av: tuple[Any, ...]) -> bool:
    """True when a repeat's ``(min, max)`` lets it match a variable number of items."""
    return av[0] != av[1]


def _unbounded(av: tuple[Any, ...]) -> bool:
    """True when a repeat may iterate more than once — the degree that actually hurts.

    Treating every nesting as ``(a+)+`` refused semver, slugs, decimals, hostnames,
    ISO-8601 durations and Windows paths — all measured well under a millisecond
    against 4 KiB of their own alphabet — so the rule was relaxed to "unbounded on the
    outside", on the stated theory that a bounded outer repeat cannot produce runaway
    backtracking however ambiguous its body is.

    That theory is false, and expensively so. What a finite bound caps is the *exponent*,
    not the cost: ``^Q(?:[a-z]+){1,40}$`` passed the relaxed screen and takes **17.5
    seconds on 32 characters**, because forty iterations over a variable body is forty
    nested choices. The bound that matters is one. A repeat that runs at most once —
    ``?``, ``{0,1}``, ``{1}`` — cannot split its input at all and is genuinely free;
    from two iterations upward there are partitions to enumerate, and the count grows
    as ``C(n-1, m-1)`` in the input length.

    Two iterations of a body whose boundary is *determined* are still fine, and that is
    what keeps the dotted-quad and the hostname loading: they are excused a step later
    by ``_anchored_body``/``_terminated_body``, on evidence about the body rather than
    on an assumption about the bound.
    """
    return av[1] is _re_const.MAXREPEAT or av[1] > 1


def _transparent(body: Any) -> list[Any]:
    """A repeat body with anchors dropped and a lone wrapping group unwrapped.

    `(?:\\.[a-z0-9]...)*` parses as a repeat over a single SUBPATTERN, so a separator
    test that looked at the body's own items saw one opaque node and gave up — which is
    why the dotted-hostname pattern stayed refused after the comma-list one was fixed.
    `_backtracking_risk` already treats a group as transparent; this is the same rule.
    """
    items = [item for item in body if item[0] is not _re_const.AT]
    while len(items) == 1 and items[0][0] is _re_const.SUBPATTERN and not (items[0][1][1] or items[0][1][2]):
        items = [item for item in items[0][1][3] if item[0] is not _re_const.AT]
    return items


def _separates(separator: frozenset[int], rest: Any) -> bool:
    """Whether ``separator`` really marks an iteration boundary in a body.

    Three conditions, and the middle two are the ones that caught this out. The rest of
    the body must not be able to *start* with the separator, must not be able to *end*
    with it — otherwise the boundary slides one character either way, which is the whole
    ambiguity — and must not be nullable, because a body that can shrink to just the
    separator is a plain repeat of a literal and proves nothing.

    Python's parser factors a common prefix, so `(a|ab)*` arrives as `a` followed by
    `(|b)`: a leading literal with a nullable tail. Reading that as "anchored by `a`"
    admitted a genuinely exponential pattern, which is why nullability is checked here
    rather than assumed away.
    """
    if rest is None or not separator:
        return False
    firsts, lasts, nullable = rest
    if nullable or firsts is None or lasts is None:
        return False
    return separator.isdisjoint(firsts) and separator.isdisjoint(lasts)


def _anchored_body(body: Any) -> bool:
    r"""Whether a repeat body opens with a separator its own tail cannot produce.

    ``(?:,\\d+)*`` and ``(?:-[a-z0-9]+)*`` are how every list and slug pattern is
    written, and they are safe for a reason the nesting rule cannot see: each iteration
    must begin with a character the rest of the body can never match, so there is
    exactly one way to split the input across iterations and nothing to backtrack over.
    ``(?:\\d+)*`` has no such separator and is the classic bomb.

    Deliberately narrow — one leading item of fixed width, and only when the remainder
    of the body cannot itself start or end with anything that item can match. Anything
    less certain falls through to the rules below, because being wrong here means
    admitting a bomb.

    A *class*, not only a literal. The test that matters is disjointness from the rest
    of the body, and `[-_]`, `[.:]` and `[/\\]` answer it exactly as `-` does — they
    are how a real pattern spells "either of these two delimiters". Insisting on a bare
    `LITERAL` refused `^(?:[a-z]+[-_]){2,4}$` and `^(?:\w+[/\\]){1,8}$` while accepting
    the single-delimiter spelling of the same shape, both measured at 0.0 ms.
    """
    items = _transparent(body)
    if len(items) < 2:
        return False
    separator = _fixed_width_alphabet(items[0])
    rest = _edges(_re_parser.SubPattern(body.state, items[1:]))
    return _separates(separator, rest)


def _fixed_width_alphabet(item: Any) -> frozenset[int]:
    """The characters a one-character item can match, or empty if it is not one.

    A separator has to consume exactly one character to mark a boundary, so a repeat, a
    group or an anchor is not one however narrow its alphabet.
    """
    edges = _edges(item)
    if edges is None:
        return frozenset()
    firsts, lasts, nullable = edges
    if nullable or firsts is None or lasts is None or firsts != lasts:
        return frozenset()
    return firsts


def _terminated_body(body: Any) -> bool:
    """Whether a repeat body *ends* with a separator its own head cannot produce.

    The mirror of :func:`_anchored_body`, and the shape every path pattern uses:
    ``(?:[^/]+/)*`` puts the delimiter last. Same argument — an iteration boundary is
    marked by a character the body cannot otherwise match, so the split is unique.
    """
    items = _transparent(body)
    if len(items) < 2:
        return False
    separator = _fixed_width_alphabet(items[-1])
    return _separates(separator, _edges(_re_parser.SubPattern(body.state, items[:-1])))


def _leaf_separates(op: Any, av: Any, neighbours: list[_Neighbour]) -> bool:
    """Whether a non-repeat opcode ends the ambiguity between the repeats around it.

    Only if the characters it can match are disjoint from every pending repeat's. A
    leaf they can also produce is not a boundary — the engine can still slide the split
    across it, which is exactly the backtracking the neighbour list is tracking.
    Anything this cannot reason about (a backreference, a lookaround, a group op that
    got here) is treated as *not* separating: keeping the pending repeats costs a
    possible false positive, dropping them costs the screen.
    """
    if not neighbours:
        return True
    points = _edges((op, av))
    if points is None:
        return False
    firsts = points[0]
    if firsts is None:
        return False
    return all(edges is None or edges[1] is None or firsts.isdisjoint(edges[1]) for _, edges, _, _ in neighbours)


def _shape_key(node: Any) -> Any:
    """A hashable, comparable form of a parse subtree (``SubPattern`` is list-like)."""
    if isinstance(node, tuple | list | _re_parser.SubPattern):
        return tuple(_shape_key(item) for item in node)
    return node


def _bucket(codepoint: int) -> int:
    """A single codepoint as an ``_ALPHABET`` member: itself if ASCII, else its bucket."""
    if codepoint < 128:
        return codepoint
    ch = chr(codepoint)
    if ch.isdigit():
        return _NON_ASCII_DIGIT
    if ch.isalnum() or ch == "_":
        return _NON_ASCII_WORD
    if ch.isspace():
        return _NON_ASCII_SPACE
    return _NON_ASCII_OTHER


def _class_codepoints(items: Any) -> frozenset[int] | None:
    """The ``_ALPHABET`` members a parsed character class can match, or None if unclear.

    Ranges reaching past ASCII contribute all four non-ASCII buckets, so an exotic range
    is over-approximated rather than assumed disjoint. None means "do not know", and the
    caller falls back to the older parse-tree comparison rather than refusing blind.
    """
    negate = False
    points: set[int] = set()
    for op, av in items:
        if op is _re_const.NEGATE:
            negate = True
        elif op is _re_const.LITERAL:
            points.add(_bucket(av))
        elif op is _re_const.RANGE:
            low, high = av
            points.update(range(low, min(high, 127) + 1))
            if high > 127:
                points |= _NON_ASCII
        elif op is _re_const.CATEGORY:
            known = _CATEGORY_SETS.get(av)
            if known is None:
                return None
            points |= known
        else:
            return None
    return frozenset(_ALPHABET - points if negate else points)


# What a subtree can match at each of its two ends, plus whether it can match nothing at
# all: (first characters, last characters, nullable). None means "cannot analyse this",
# and the caller falls back to parse-tree equality rather than refusing blind.
_Edges = tuple[frozenset[int], frozenset[int], bool]

_ZERO_WIDTH: _Edges = (frozenset(), frozenset(), True)


def _edges(node: Any) -> _Edges | None:
    """The characters a repeat body can begin and end with, and whether it can be empty.

    This used to be a single set and only answered for one-character bodies, which meant
    every multi-character body — `(zz)+`, `([b-d]{2})+`, `(xx)+` — came back "do not know"
    and skipped the overlap test entirely, so `^(?:zz)+(?:zzz)+(?:zzzzz)+$` loaded and then
    spent seconds per argument. A body is a *sequence*, though, and a sequence's ends are
    derivable: what it can start with, what it can end with, and whether it can vanish.
    Two adjacent repeats are ambiguous exactly when the run of the first can hand a
    character to the second, so the ends are what the overlap test actually needs — the
    middle of a body never sits on the boundary between two repeats.
    """
    if isinstance(node, list | _re_parser.SubPattern):
        return _sequence_edges(node)
    if not (isinstance(node, tuple) and len(node) == 2):
        return None
    op, av = node
    if op is _re_const.LITERAL:
        single = frozenset({_bucket(av)})
        return (single, single, False)
    if op is _re_const.NOT_LITERAL:
        rest = _ALPHABET - {_bucket(av)}
        return (rest, rest, False)
    if op in (_re_const.ANY, _re_const.ANY_ALL):
        any_char = _ALPHABET if op is _re_const.ANY_ALL else _ALPHABET - {ord("\n")}
        return (any_char, any_char, False)
    if op is _re_const.IN:
        points = _class_codepoints(av)
        return None if points is None else (points, points, False)
    if op in _BACKTRACKING_REPEATS or op in _ATOMIC_REPEATS:
        inner = _edges(av[2])
        return None if inner is None else (inner[0], inner[1], inner[2] or av[0] == 0)
    if op is _re_const.SUBPATTERN:
        # av is (group, add_flags, del_flags, body); an inline `(?i:...)` changes which
        # characters the body matches in a way this analysis does not model, so it is a
        # "do not know" rather than a wrong answer.
        return None if av[1] or av[2] else _edges(av[3])
    if op is _re_const.ATOMIC_GROUP:
        return _edges(av)
    if op is _re_const.BRANCH:
        return _branch_edges(av[1])
    if op is _re_const.AT or op in (_re_const.ASSERT, _re_const.ASSERT_NOT):
        return _ZERO_WIDTH  # zero-width: it constrains the boundary but never occupies it
    return None


def _sequence_edges(seq: Any) -> _Edges | None:
    """Fold a sequence's items into one ``_Edges``, from both ends inwards."""
    items = list(seq)
    first: set[int] = set()
    last: set[int] = set()
    nullable = True
    for item in items:
        edges = _edges(item)
        if edges is None:
            return None
        first |= edges[0]
        if not edges[2]:
            break
    for item in reversed(items):
        edges = _edges(item)
        if edges is None:
            return None
        last |= edges[1]
        if not edges[2]:
            nullable = False
            break
    return (frozenset(first), frozenset(last), nullable)


def _branch_edges(branches: Any) -> _Edges | None:
    first: set[int] = set()
    last: set[int] = set()
    nullable = False
    for branch in branches:
        edges = _edges(branch)
        if edges is None:
            return None
        first |= edges[0]
        last |= edges[1]
        nullable = nullable or edges[2]
    return (frozenset(first), frozenset(last), nullable)


# A variable repeat still adjacent to whatever comes next: its shape, its ends, whether
# its body is a bare `.` (which the trailing-repeat exemption below has to know), and how
# many times it may iterate — clamped to the longest argument the gate will hand it,
# because a cap above that is not a cap.
_Neighbour = tuple[Any, _Edges | None, bool, int]


def _clashes(a: _Neighbour, b: _Neighbour) -> bool:
    """Whether the boundary between two adjacent variable repeats can move.

    It can only move if some character is both a legal *end* of the earlier body and a
    legal *start* of the later one — which is why `(?:ab)+(?:cd)+` is fine and
    `(?:ab)+(?:bc)+` is not.
    """
    prev_key, prev_edges, _, _ = a
    key, edges, _, _ = b
    if edges is not None and prev_edges is not None:
        return bool(prev_edges[1] & edges[0])
    return prev_key == key


# How much work a run of mutually ambiguous variable repeats may cost.
#
# The rule used to be a *count* — one repeat, and a second one adjacent to it refused the
# pattern. The measurements it was set from are all unbounded repeats, under
# `re.fullmatch` (which is how the gate applies a pattern), on input built from the
# pattern's own alphabet and failing at the last character:
#
#     \d+\d+                                     2 runs      49 ms at 4 KiB
#     [A-Za-z0-9]+[A-Za-z0-9_-]+                 2 runs      38 ms
#     ^.+,[^\n]+$                                2 runs      14 ms
#     [A-Za-z0-9]+[A-Za-z0-9_-]+[A-Za-z0-9]+     3 runs   6 000 ms at 2 KiB
#     ^.+,[^\n]+,[^\n]+$                         3 runs   9 588 ms
#     [a-z]+[a-z]+[a-z]+[a-z]+                   4 runs  13 800 ms at 500 B
#
# Counting refuses those correctly and refuses a great deal else with them, because a
# `+` and a `{1,10}` counted the same. `^[a-zA-Z]{1,10}[a-zA-Z0-9]{0,20}$` — a username
# validator, and the shape half the MCP servers in the wild ship — was refused at import,
# as were `^\w{1,64}\w{1,64}$` and `^[a-z]{1,100}[a-z0-9]{1,100}$`. Measured on the same
# 4 KiB failing input: 0.00 ms, 0.03 ms, 0.05 ms. Refusing those buys nothing and costs
# the import.
#
# What the cost actually tracks is the number of ways the run can split its input, which
# is the *product* of the caps, not how many of them there are (each cap clamped to
# `_MAX_PATTERN_INPUT`, since a bound above the longest possible argument is not a bound).
# Measured on `^[a-z]{1,c}[a-z]{1,c}$` and its three-repeat sibling, same 4 KiB input:
#
#     product        pair          triple
#       1 024      0.008 ms
#       4 096      0.028 ms      0.157 ms
#      16 384      0.109 ms      1.278 ms
#     262 144      1.575 ms      9.937 ms   (c=512 pair / c=128 triple)
#      16 777 216  37.832 ms     ~600 ms
#
# So ~6 ns per split, and a product is a good predictor across both shapes. The threshold
# is set at four million — about 24 ms predicted, half the probe's 50 ms budget — so the
# shapes that are genuinely quadratic-with-a-large-constant are still refused at load
# (`\d+\d+` is 4 096², sixteen million), the cheap bounded ones load, and anything in
# between still has to get past the timing probe, which measures rather than predicts.
#
# The bargain is unchanged: a false positive is a loud load-time error naming a rewrite,
# a false negative is a hung process. What changed is that the estimate is no longer
# 200 000× out on the ordinary case.
_MAX_AMBIGUOUS_SPLITS = 4_000_000


def _repeat_cap(av: tuple[Any, ...]) -> int:
    """How many times this repeat may iterate, clamped to the longest argument."""
    high = av[1]
    if high is _re_const.MAXREPEAT:
        return _MAX_PATTERN_INPUT
    return min(int(high), _MAX_PATTERN_INPUT)


def _neighbour_clash(neighbours: list[_Neighbour], candidate: _Neighbour) -> str | None:
    """Whether adding ``candidate`` makes the ambiguous run cost more than we allow."""
    clashing = [n for n in neighbours if _clashes(n, candidate)]
    if not clashing:
        return None
    splits = candidate[3]
    for n in clashing:
        splits *= n[3]
        if splits > _MAX_AMBIGUOUS_SPLITS:
            break
    if splits <= _MAX_AMBIGUOUS_SPLITS:
        return None
    _, edges, _, _ = candidate
    if edges is not None and any(e is not None for _, e, _, _ in clashing):
        return "two repeats in a row that can match the same character, e.g. `[a-z]+[a-z0-9]+`"
    return "the same thing repeated twice in a row, e.g. `\\d+\\d+`"


def _is_dot(body: Any) -> bool:
    """True for a repeat body that is exactly `.` — the one thing a trailing repeat may be."""
    while isinstance(body, tuple | list | _re_parser.SubPattern) and len(body) == 1:
        body = body[0]
    return isinstance(body, tuple) and len(body) == 2 and body[0] in (_re_const.ANY, _re_const.ANY_ALL)


def _backtracking_risk(
    seq: Any,
    *,
    in_repeat: bool,
    at_tail: bool,
    neighbours: list[_Neighbour] | None = None,
    held: list[_Edges | None] | None = None,
) -> str | None:
    """Describe the first runaway-backtracking shape in a parsed pattern, if any.

    ``at_tail`` says this sequence's end is also the end of the whole pattern; ``neighbours``
    is the caller's own adjacency list, threaded through so a group is transparent to it.
    """
    # variable repeats reachable from here without consuming a character; anything that
    # must consume one clears the list, since it is what disambiguates the two sides.
    if neighbours is None:
        neighbours = []
    # the characters of a leaf that the repeats before it could also match, held until
    # the next repeat says whether it can match them too.
    #
    # A one-element box rather than a local, for the same reason `neighbours` is a list
    # the caller owns: a group has to be transparent to it. `^.+,\d+$` loaded and
    # `^.+,(\d+)$` — the same pattern with one pair of parentheses — was refused,
    # because the recursion into the group started with an empty hold and never learned
    # that the comma before it was already spoken for.
    if held is None:
        held = [None]
    items = list(seq)
    # the last item that can occupy a character: an anchor after it is not "after" it in
    # any sense that matters, so `[a-z]+.*$` has `.*` in tail position just like `[a-z]+.*`.
    final = max((i for i, (op, _) in enumerate(items) if op is not _re_const.AT), default=-1)
    for index, (op, av) in enumerate(items):
        tail = at_tail and index == final
        if op in _BACKTRACKING_REPEATS:
            variable_repeat = _variable_width(av)
            if in_repeat and variable_repeat:
                return "a variable-length repeat nested inside another repeat, e.g. `(a+)+`"
            dot_repeat = _is_dot(av[2])
            trailing_dot = variable_repeat and tail and op is _re_const.MAX_REPEAT and dot_repeat
            if trailing_dot and not any(previous_dot for _, _, previous_dot, _ in neighbours):
                # a greedy `.`-repeat with nothing after it swallows the rest of the input on
                # its first try and never has to give any of it back, so it cannot be the
                # second half of an ambiguous pair. Refusing it cost `^\s*[-*]\s+.+$` and
                # `^\w+.+$` — ordinary log/markdown rules, measured at 0.00 s on 4 KiB of
                # anything — and bought nothing, because `.` intersects almost every class
                # and so clashed with whatever preceded it. The worst input it still admits
                # is a newline, which `.` will not cross: 30 ms at the 4 KiB cap, quadratic
                # with a tiny constant, and that is the trade being made here.
                #
                # It does not extend to a `.`-repeat that *follows another one*. `.*.+` is one
                # greedy run split two ways — the same thing repeated twice — and the "nothing
                # after it" argument says nothing about the pair. `^[^/]+[b-d]{3}?.*.+$` is
                # 39 s at 4 KiB and was found by exempting it.
                continue
            # Only an unbounded repeat contributes a *degree*. `[01]?\d?\d` is three
            # overlapping repeats and four possible splits — the IPv4 octet every policy
            # author writes — and refusing it bought nothing.
            # A separator only one side can absorb is still a separator. In
            # `[A-Za-z0-9.-]+\.[A-Za-z]{2,}` the dot is in the left class and not the
            # right, so the only freedom is *which* dot is the last one — linear, and
            # measured at 0.03 ms on 4 KiB. In `^.+,[^\n]+,[^\n]+$` both sides match a
            # comma, every comma is a free choice, and that is the 518 ms case.
            body_edges = _edges(av[2])
            # A leaf the pending repeats could also match was held in `held`, and this
            # repeat decides what it meant. If this repeat cannot match it, the boundary
            # between the two is pinned — and *only* that boundary.
            #
            # It used to clear the whole list, which threw away repeats it had never
            # compared with anything. `^.+,\d+,.+,\d+,.+$` is the shape that exposed it:
            # each `\d+` is pinned by the commas around it, so each one wiped both `.+`
            # runs standing to its left, and the three `.+` runs — which *can* all absorb
            # a comma, and are free with respect to each other — were never seen
            # together. Measured 1 243 ms at 2 000 characters and 9 442 ms at 4 000,
            # loading clean.
            #
            # So a pinned repeat drops out of the run instead of emptying it, and the
            # repeats that can still absorb the separator stay in.
            pinned = False
            if held[0] is not None and body_edges is not None:
                incoming, separator = body_edges[0], held[0][0]
                if incoming is not None and separator is not None and incoming.isdisjoint(separator):
                    pinned = True
                    neighbours[:] = [n for n in neighbours if n[1] is None or n[1][1] & separator]
                held[0] = None
            # A pin excuses the *check*, never the *registration*. The disjointness test
            # reads `body_edges[0]` — the body's firsts — so all it establishes is that
            # this repeat's LEFT boundary cannot move. Dropping the repeat from the run
            # on that evidence declared its RIGHT boundary safe too, and nothing had
            # looked at it: the next repeat over the same alphabet then saw an empty run
            # and loaded as a run of one. `^[a-z.-]+\.\d+\d+.+$` is the shape —
            # `\d+\d+` is the canonical quadratic pattern, and putting a separator in
            # front of it was enough to admit it. Measured at 4 168 ms on 2 000
            # characters, while the structurally identical `^\d+\d+\d+$` is refused.
            neighbour = (
                (_shape_key(av[2]), body_edges, dot_repeat, _repeat_cap(av))
                if variable_repeat and _unbounded(av)
                else None
            )
            if neighbour is not None and not pinned:
                clash = _neighbour_clash(neighbours, neighbour)
                if clash is not None:
                    return clash
            # A repeat that must consume separates what is on either side of it. So does
            # one that *may* be empty but opens with its own separator when it is not:
            # `[a-z0-9]+(?:-[a-z0-9]+)*` reads as two overlapping repeats only if the `-`
            # is ignored, and with it there is exactly one way to split the input. That
            # elision refused slugs, comma lists and dotted hostnames.
            # A body carrying its own separator has exactly one valid split whatever it
            # contains, so it ends the run outright: `[a-z0-9]+(?:-[a-z0-9]+)*` reads as
            # two overlapping repeats only if the `-` is ignored.
            #
            # A repeat that *must* consume also separates — but only what it is disjoint
            # from, which is the same test a leaf gets. Clearing the run whenever
            # `av[0] != 0` was the blunt version, and it separated `.+` from `[^\n]+` in
            # `^.+,[^\n]+,[^\n]+$` on the strength of the middle run consuming a
            # character it could equally have left to either side. `\w+\s+\w+` is the
            # case that needs the rule: `\s` cannot be a `\w`, so the boundary is
            # forced and the two `\w+` runs are not neighbours at all.
            if _anchored_body(av[2]) or _terminated_body(av[2]):
                neighbours.clear()
            elif av[0] != 0 and body_edges is not None:
                spanned = body_edges[0] | body_edges[1]
                neighbours[:] = [n for n in neighbours if n[1] is None or n[1][1] & spanned]
            if neighbour is not None:
                neighbours.append(neighbour)
            # `in_repeat` means "enclosed by a repeat whose iterations are ambiguous".
            # Two things make them unambiguous, and both were being ignored: a bounded
            # outer repeat cannot iterate enough times for its body's ambiguity to cost
            # anything (`(a+)?`), and a body carrying its own separator has exactly one
            # valid split whatever it contains (`(?:,\d+)*`, `(?:[^/]+/)*`). Between
            # them they account for semver, slugs, comma lists, hostnames, IPv6, ISO-8601
            # durations and Windows paths — every one measured under a millisecond.
            ambiguous = variable_repeat and _unbounded(av) and not _anchored_body(av[2]) and not _terminated_body(av[2])
            risk = _backtracking_risk(av[2], in_repeat=in_repeat or ambiguous, at_tail=False)
        elif op is _re_const.BRANCH:
            if in_repeat:
                return "an alternation inside a repeat, e.g. `(a|ab)*` — use a character class"
            neighbours.clear()
            risk = next((r for b in av[1] if (r := _backtracking_risk(b, in_repeat=False, at_tail=tail))), None)
        elif op is _re_const.SUBPATTERN:
            # a group is transparent here. It used to clear the adjacency list and recurse
            # into a fresh one, so `([a-z]+)[a-z0-9]+` — the same quadratic pattern as
            # `[a-z]+[a-z0-9]+`, with one pair of parentheses — was invisible to the shape
            # screen and left to the timing probe, which decided it by wall clock.
            risk = _backtracking_risk(av[3], in_repeat=in_repeat, at_tail=tail, neighbours=neighbours, held=held)
        elif op in (_re_const.ASSERT, _re_const.ASSERT_NOT):
            # A lookaround runs its own match, so it starts a fresh analysis. It consumes
            # nothing, so it does not separate the repeats on either side of it either.
            risk = _backtracking_risk(av[1], in_repeat=False, at_tail=False)
        elif op is _re_const.ATOMIC_GROUP or op in _ATOMIC_REPEATS:
            neighbours.clear()
            body = av[2] if op in _ATOMIC_REPEATS else av
            risk = _backtracking_risk(body, in_repeat=False, at_tail=False)
        elif op is _re_const.GROUPREF_EXISTS:
            neighbours.clear()
            branches = (b for b in av[1:] if b)
            risk = next((r for b in branches if (r := _backtracking_risk(b, in_repeat=in_repeat, at_tail=tail))), None)
        elif op is _re_const.AT:
            risk = None  # an anchor matches the empty string, so it separates nothing
        else:
            # A leaf separates the repeats around it only if it is a character neither
            # of them can produce. Clearing unconditionally read `,` in
            # `^.+,[^\n]+,[^\n]+$` as a boundary — and `.` and `[^\n]` both match a
            # comma, so it marks nothing and the three runs stay mutually ambiguous.
            # Measured 518 ms at 2 000 characters of comma-rich input, which is the
            # finding this whole screen was rewritten to close, reopened one opcode
            # away. Disjointness is the same test `_separates` applies to a repeat body.
            if _leaf_separates(op, av, neighbours):
                neighbours.clear()
                held[0] = None
            else:
                # The leaf is inside the pending repeats' alphabet, so it does not end
                # the ambiguity on its own — but it may still end it from the right. Held
                # until the next repeat is known: if that one cannot match this
                # character, the split point is forced and there is nothing to search.
                held[0] = _edges((op, av))
            risk = None  # every remaining opcode is a leaf (literal, class, backref)
        if risk is not None:
            return risk
    return None


# The AST screen reasons about shape, and some ambiguity is invisible to it: an inline
# `(?i)` it does not model, overlapping ranges finer-grained than the four non-ASCII
# buckets. So a pattern that survives the screen is also *run*, once, at load time,
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


def _reject_catastrophic_backtracking(pattern: str, compiled: re.Pattern[str]) -> None:
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


# Which declared types actually consult each keyword. `any` is exempt from all of it:
# a field with no declared type is the one place a bound cannot be shown to be dead.
_KEYWORD_APPLIES_TO: dict[str, frozenset[str]] = {
    # `_check_string_value`, reached for a string scalar and for each element of an
    # array whose `item_type` is string.
    "max_length": frozenset({"string", "array"}),
    "min_length": frozenset({"string", "array"}),
    "pattern": frozenset({"string", "array"}),
    # `_check_number`, reached the same two ways.
    "minimum": frozenset({"integer", "number", "array"}),
    "maximum": frozenset({"integer", "number", "array"}),
    "exclusive_minimum": frozenset({"integer", "number", "array"}),
    "exclusive_maximum": frozenset({"integer", "number", "array"}),
    "multiple_of": frozenset({"integer", "number", "array"}),
    # Consulted only inside `if spec.type == "array"`.
    "max_items": frozenset({"array"}),
    "min_items": frozenset({"array"}),
    "item_enum": frozenset({"array"}),
    "item_type": frozenset({"array"}),
    "unique_items": frozenset({"array"}),
}


def _check_bound(name: str, value: Any) -> None:
    """A numeric bound must be a real, finite, comparable number.

    NaN makes every IEEE comparison False and ±Inf makes one side of every
    comparison True, so a non-finite bound is a bound that never fires — the exact
    silent fail-open this module refuses for non-finite *values*. An integer past
    the float range is worse still: it survives load and then raises OverflowError
    from inside the gate, where a decision was owed.
    """
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyError(f"{name} must be a number, got {type(value).__name__}", code="invalid_field")
    if isinstance(value, float) and not math.isfinite(value):
        raise PolicyError(
            f"{name} is {value!r} — a non-finite bound never fires (every comparison against NaN is "
            "False, and every value satisfies ±Inf), so it would read as a bound and enforce nothing",
            code="invalid_field",
        )
    if abs(value) > _MAX_BOUND:
        raise PolicyError(
            f"{name} has {len(str(abs(value)))} digits, past the range a float can compare against — "
            "evaluating it would raise OverflowError from inside the gate instead of returning a decision",
            code="invalid_field",
        )


def _check_length_bound(name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"{name} must be a non-negative integer, got {value!r}", code="invalid_field")


@dataclass(frozen=True)
class Field:
    """One field in a :class:`Schema`.

    ``sensitive`` is only meaningful on a *return* schema: ``"pii"`` or
    ``"secret"`` fields are redacted by the post-gate unless the caller's role is
    explicitly allowed to see them.
    """

    type: str = "string"
    required: bool = True
    enum: tuple[Any, ...] | None = None
    max_length: int | None = None
    min_length: int | None = None
    pattern: str | None = None
    sensitive: str | None = None  # None | "pii" | "secret"
    #: Whether an explicit ``None`` is a legal value for this field.
    #:
    #: Distinct from ``required``, which is about the key being *present*. An optional
    #: Python parameter (`note: str | None = None`) and a JSON Schema
    #: `anyOf: [T, null]` both say the value may be null, and both imported as a plain
    #: `string` — so a caller passing the null the source explicitly allows was denied
    #: `arg_schema`, with nothing in the policy format able to express what it wanted.
    nullable: bool = False
    item_type: str | None = None  # element type for "array"
    #: Element-count bounds for an ``array``. `maxItems` is a bound the source author
    #: wrote and the projection had nowhere to put, so an ordinary
    #: `list[str] = Field(max_length=10)` refused the whole tool rather than lose it.
    #: Distinct from ``max_length``, which bounds each string *element*.
    max_items: int | None = None
    min_items: int | None = None
    #: Allowed values for each *element* of an ``array``.
    #:
    #: Distinct from ``enum``, which the engine matches against the whole argument — so
    #: copying an element enum there would deny every call. Carried as an escaped
    #: alternation in ``pattern`` for one release, which worked for strings and left
    #: `{"type": "array", "items": {"type": "integer", "enum": [1, 2]}}` unimportable
    #: because there was nothing to hang a value set on that was not a string screen.
    item_enum: tuple[Any, ...] | None = None
    #: Whether every element of an ``array`` must be distinct.
    #:
    #: The same case `max_items` was rescued from, left behind in the same pass:
    #: `uniqueItems` is what every pydantic `set[T]` emits, and refusing a bound a real
    #: source writes cost the whole tool rather than the bound. Compared by equality
    #: rather than by hash, so a list of dicts — which is what a `set[Model]` becomes
    #: once it is JSON — is checked too.
    unique_items: bool = False
    # Numeric value bounds (integer/number, and per numeric array element). A
    # non-finite value (NaN/±Inf) is denied outright — a NaN makes every IEEE
    # comparison False, so a naive `<=` bound would silently pass it (Phase 0.1).
    minimum: float | None = None
    maximum: float | None = None
    exclusive_minimum: float | None = None
    exclusive_maximum: float | None = None
    multiple_of: float | None = None

    def __post_init__(self) -> None:
        # Every failure here is a PolicyError: a malformed field is a structural
        # problem in the policy, and a host that wraps `load_policy` in the
        # documented `except PolicyError: fail_closed()` must catch it rather than
        # take an unhandled ValueError on a typo.
        if self.type not in _TYPE_CHECKS:
            raise PolicyError(f"unknown field type: {self.type!r}", code="invalid_field")
        if self.sensitive not in (None, "pii", "secret"):
            raise PolicyError(f"sensitive must be None|'pii'|'secret', got {self.sensitive!r}", code="invalid_field")
        for bound in ("minimum", "maximum", "exclusive_minimum", "exclusive_maximum", "multiple_of"):
            _check_bound(bound, getattr(self, bound))
        for bound in ("max_length", "min_length", "max_items", "min_items"):
            _check_length_bound(bound, getattr(self, bound))
        # A bound consulted only under one `type` reads as enforced and enforces nothing
        # anywhere else, so every keyword is checked against the types that actually
        # consult it. This was a hand-written list covering the array keywords only, and
        # its own stated rule caught its siblings: `_check_scalar` applies the numeric
        # bounds only under `if spec.type in ("integer", "number")` and the string bounds
        # only under `isinstance(value, str)`, so `Field(type="string", maximum=10)` and
        # `Field(type="integer", pattern="^a+$")` loaded clean and checked nothing —
        # exactly the case the list was written for, one keyword to the side.
        #
        # `string` and `array` share the string and numeric bounds because an array's
        # elements are checked with the same two helpers, which is how
        # `item_type="string", max_length=8` bounds each element.
        for attr, applies_to in _KEYWORD_APPLIES_TO.items():
            if self.type in applies_to or self.type == "any":
                continue
            declared = getattr(self, attr)
            if declared is None or declared is False:
                continue
            raise PolicyError(
                f"{attr} is only meaningful on {' or '.join(sorted(applies_to))}, and this field is "
                f"{self.type!r} — it would read as a bound and enforce nothing",
                code="invalid_field",
            )
        if self.min_items is not None and self.max_items is not None and self.min_items > self.max_items:
            raise PolicyError(
                f"min_items {self.min_items} is greater than max_items {self.max_items}, so no value can "
                "ever satisfy this field",
                code="invalid_field",
            )
        if self.multiple_of is not None and self.multiple_of == 0:
            raise PolicyError(f"multiple_of must be non-zero, got {self.multiple_of!r}", code="invalid_field")
        if self.pattern is not None:
            if not isinstance(self.pattern, str):
                raise PolicyError(f"pattern must be a string, got {type(self.pattern).__name__}", code="invalid_field")
            # Compile eagerly so an invalid regex fails LOUDLY at policy-load
            # instead of silently fail-closing every call at runtime, and screen it
            # for catastrophic backtracking in the same pass — an imported pattern
            # is attacker-influenced input and gets checked before it can run.
            try:
                compiled = re.compile(self.pattern)
            except re.error as exc:
                raise PolicyError(f"invalid regex pattern {self.pattern!r}: {exc}", code="invalid_field") from exc
            _reject_catastrophic_backtracking(self.pattern, compiled)


@dataclass(frozen=True)
class Schema:
    """An ordered map of field-name → :class:`Field`.

    ``allow_extra=False`` (the default) means an argument not named in the schema
    is rejected — deny-by-default extended to the argument surface.
    """

    fields: dict[str, Field] = field(default_factory=dict)
    allow_extra: bool = False


def _check_string_value(name: str, spec: Field, value: str) -> list[str]:
    """Length and pattern checks for a string — a scalar arg *or* one array element.

    The absolute ``_MAX_PATTERN_INPUT`` cap is a DoS/ReDoS bound and always applies;
    ``max_length`` and ``pattern`` apply when declared. At most one error is
    reported (the first that fails), matching the scalar path.
    """
    if len(value) > _MAX_PATTERN_INPUT:
        return [f"{name}: value too long ({len(value)} > {_MAX_PATTERN_INPUT})"]
    if spec.min_length is not None and len(value) < spec.min_length:
        return [f"{name}: shorter than min_length {spec.min_length}"]
    if spec.max_length is not None and len(value) > spec.max_length:
        return [f"{name}: longer than max_length {spec.max_length}"]
    if spec.pattern is not None and not re.fullmatch(spec.pattern, value):
        return [f"{name}: does not match required pattern"]
    return []


def _check_unique(name: str, value: Sequence[Any]) -> list[str]:
    """`unique_items`, in linear time for anything a hash can separate.

    The first version was an equality scan against a growing list, on the reasoning that
    once a `set[Model]` has been through JSON it is a list of dicts and `set()` on that
    raises rather than deduplicating. True, and it made the check O(n^2) on the one
    input an attacker chooses freely. It runs at pre-gate step 3, *before* the output
    size budget at step 5, and `re` is not the only thing in this process that does not
    release the GIL: 8 000 distinct integers cost 461 ms of held CPU, per call, for a
    payload that builds in under a millisecond. The duplicate case short-circuits, so
    only the *valid* payload is expensive — which is the one an attacker sends.

    Hashable elements go in a set, which is exact and linear. Unhashable ones — dicts and
    lists, the `set[Model]`-through-JSON case — fall back to the equality scan, but only
    against each other, and under a bound: past `_MAX_EQUALITY_SCAN` of them the field is
    refused rather than scanned, because "this costs too much to check" and "this is
    fine" are not the same answer. A caller who needs more than that on unhashable
    elements has a `max_items` to declare.
    """
    hashed: set[Any] = set()
    unhashable: list[Any] = []
    for item in value:
        try:
            if item in hashed:
                return [f"{name}: has a repeated element, and unique_items is set"]
            hashed.add(item)
        except TypeError:
            if len(unhashable) >= _MAX_EQUALITY_SCAN:
                return [
                    f"{name}: has more than {_MAX_EQUALITY_SCAN} elements that cannot be hashed, "
                    "and unique_items cannot be checked on them without a quadratic scan — "
                    "declare max_items, or drop unique_items for this field"
                ]
            if item in unhashable:
                return [f"{name}: has a repeated element, and unique_items is set"]
            unhashable.append(item)
    return []


# Unhashable elements cost an equality scan each. 512 of them is about 130 000
# comparisons — under a millisecond on the shapes this sees — and the wall past which
# the field is refused instead of checked.
_MAX_EQUALITY_SCAN = 512


def _check_number(name: str, spec: Field, value: int | float) -> list[str]:
    """Value bounds for a number — a scalar arg or one numeric array element.

    A non-finite float (NaN/±Inf) is denied first: it cannot satisfy a bound
    consistently, so allowing it would be a silent fail-open.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return [f"{name}: non-finite number is not allowed"]
    if spec.minimum is not None and value < spec.minimum:
        return [f"{name}: below minimum {spec.minimum}"]
    if spec.maximum is not None and value > spec.maximum:
        return [f"{name}: above maximum {spec.maximum}"]
    if spec.exclusive_minimum is not None and value <= spec.exclusive_minimum:
        return [f"{name}: not above exclusive_minimum {spec.exclusive_minimum}"]
    if spec.exclusive_maximum is not None and value >= spec.exclusive_maximum:
        return [f"{name}: not below exclusive_maximum {spec.exclusive_maximum}"]
    if spec.multiple_of is not None:
        if isinstance(value, int) and isinstance(spec.multiple_of, int):
            ok = value % spec.multiple_of == 0
        else:
            q = value / spec.multiple_of
            ok = math.isclose(q, round(q), rel_tol=1e-9, abs_tol=1e-9)
        if not ok:
            return [f"{name}: not a multiple of {spec.multiple_of}"]
    return []


def _check_scalar(name: str, spec: Field, value: Any) -> list[str]:
    errors: list[str] = []
    # A declared-nullable field accepts the null and stops there: every bound below
    # describes a value, and `None` is the absence of one.
    if value is None and spec.nullable:
        return errors
    expected = _TYPE_CHECKS[spec.type]

    # bool is a subclass of int/float — keep numbers distinct from booleans.
    if spec.type in ("integer", "number") and isinstance(value, bool):
        return [f"{name}: expected {spec.type}, got boolean"]
    if spec.type != "any" and not isinstance(value, expected):
        return [f"{name}: expected {spec.type}, got {type(value).__name__}"]

    if spec.enum is not None and value not in spec.enum:
        errors.append(f"{name}: not one of the allowed values {list(spec.enum)}")

    if isinstance(value, str):
        errors.extend(_check_string_value(name, spec, value))
    if spec.type in ("integer", "number"):
        errors.extend(_check_number(name, spec, value))

    if spec.type == "array" and isinstance(value, (list, tuple)):
        if spec.min_items is not None and len(value) < spec.min_items:
            errors.append(f"{name}: has {len(value)} items, fewer than min_items {spec.min_items}")
        if spec.max_items is not None and len(value) > spec.max_items:
            errors.append(f"{name}: has {len(value)} items, more than max_items {spec.max_items}")
        if spec.unique_items:
            errors.extend(_check_unique(name, value))

    if spec.type == "array" and spec.item_enum is not None and isinstance(value, (list, tuple)):
        allowed = spec.item_enum
        errors.extend(
            f"{name}[{i}]: not one of the allowed values {list(allowed)}"
            for i, item in enumerate(value)
            if item not in allowed
        )

    if spec.type == "array" and spec.item_type is not None:
        item_expected = _TYPE_CHECKS.get(spec.item_type, object)
        numeric_item = spec.item_type in ("integer", "number")
        for i, item in enumerate(value):
            iname = f"{name}[{i}]"
            if numeric_item and isinstance(item, bool):
                errors.append(f"{iname}: expected {spec.item_type}, got boolean")
            elif spec.item_type != "any" and not isinstance(item, item_expected):
                errors.append(f"{iname}: expected {spec.item_type}, got {type(item).__name__}")
            elif spec.item_type == "string" and isinstance(item, str):
                # Bound each string element by the same length/pattern caps as a
                # scalar string — otherwise a huge or malformed element bypasses the
                # scalar bounds and flows into the canary scan and the tool. Nested
                # objects are still only shallow-checked.
                errors.extend(_check_string_value(iname, spec, item))
            elif numeric_item:
                errors.extend(_check_number(iname, spec, item))
    return errors


def validate(schema: Schema, data: dict[str, Any]) -> list[str]:
    """Return a list of human-readable validation errors (empty = valid).

    **No error here ever interpolates an argument value.** These strings become the
    ``reason`` on a ``GateDecision``, which is written to the audit record and put in
    the ``GateDenied`` message — both of which the docs promise carry only a keyed
    digest of the arguments. An enum or bound violation naming the value it rejected
    would put the rejected PII (or a canary token, since ``arg_schema`` is evaluated
    before the canary check) verbatim into a log file. Names, types and the
    *declared* bounds are policy, not caller data, and are safe to state.
    """
    errors: list[str] = []

    for fname, spec in schema.fields.items():
        if fname not in data:
            if spec.required:
                errors.append(f"{fname}: required but missing")
            continue
        errors.extend(_check_scalar(fname, spec, data[fname]))

    if not schema.allow_extra:
        for key in data:
            if key not in schema.fields:
                errors.append(f"{key}: unexpected argument (not in schema)")

    return errors


def sensitive_fields(schema: Schema, *, allowed: frozenset[str] = frozenset()) -> list[str]:
    """Names of fields marked sensitive that the caller is *not* allowed to see.

    ``allowed`` is ``Principal.can_view``: the **sensitivity classes** — ``"pii"`` /
    ``"secret"`` — this caller may receive in the clear. Classes, not field names,
    because that is what the policy marks and what the docs document; matching field
    names instead made the documented `can_view={"pii"}` silently redact everything,
    and made an escape hatch out of a name the policy never published.

    Anything in ``allowed`` that is not a class this engine knows matches nothing, so
    a typo or a stale name redacts rather than discloses.
    """
    return [
        name for name, spec in schema.fields.items() if spec.sensitive is not None and spec.sensitive not in allowed
    ]
