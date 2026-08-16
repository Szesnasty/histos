"""What each piece of a parsed pattern can match, and where two pieces can touch.

Split out of `schema.py`. The screen reads `re`\'s own parse tree — private modules,
deliberately: the alternative is a second regex parser, and a screen that disagrees with
the engine it is protecting is worse than none. Every judgement further up is expressed
as a question about *codepoints*, which is what this module computes.

Non-ASCII is bucketed rather than enumerated: four sentinels stand for "some digit above
127", "some word character", "some space", "everything else", so `\\w` and `[À-ÿ]` can be
compared for overlap without materialising a million-element set.
"""

from __future__ import annotations

# The private modules on purpose: the alternative is a second regex parser, and a
# screen that disagrees with the engine it is protecting is worse than no screen.
import re._constants as _re_const
import re._parser as _re_parser
from typing import Any

from histos._bounds import _MAX_PATTERN_INPUT as _MAX_PATTERN_INPUT

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

# A variable repeat still adjacent to whatever comes next: its shape, its ends,
# whether its body is a bare `.`, and how many times it may iterate. Declared here
# rather than with the screen that uses it, because `_leaf_separates` below reads
# it and the two modules cannot import each other.
_Neighbour = tuple[Any, _Edges | None, bool, int]


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
