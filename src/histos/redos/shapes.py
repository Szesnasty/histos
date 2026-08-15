from __future__ import annotations

# The private modules on purpose: the alternative is a second regex parser, and a
# screen that disagrees with the engine it is protecting is worse than no screen.
import re._constants as _re_const
import re._parser as _re_parser
from typing import Any

from histos.redos.alphabet import (
    _ATOMIC_REPEATS,
    _BACKTRACKING_REPEATS,
    _MAX_PATTERN_INPUT,
    _anchored_body,
    _Edges,
    _edges,
    _leaf_separates,
    _Neighbour,
    _shape_key,
    _terminated_body,
    _unbounded,
    _variable_width,
)

# because a cap above that is not a cap.


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
