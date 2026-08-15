"""The ReDoS screen after it learned about *polynomial* backtracking.

The screen used to refuse only exponential shapes, and told the reader in a comment
that `_MAX_PATTERN_INPUT` bounded everything else. It did not: adjacent repeats over
overlapping-but-differently-spelled classes are a polynomial *degree*, and at degree
three or four a 4 KiB argument is tens of seconds to hours with the GIL held. Every
pattern below that is now refused used to import in microseconds and then hang.

The other half of this file is the false-positive side, which matters just as much:
a screen that refuses a legitimate pattern breaks a working deployment at load.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from histos import Field, PolicyError, Schema, load_policy
from histos.policy.schema import validate
from histos.redos.alphabet import _MAX_PATTERN_INPUT
from histos.redos.probe import _PROBE_BUDGET_S

REPO = Path(__file__).resolve().parent.parent

# ── polynomial shapes the old screen let through ─────────────────────────

# Each of these was accepted by the pre-fix screen. The first is the review's headline
# case — an email rule an author would write without a second thought — and the third
# was measured at 48 s on one 4096-character argument.
POLYNOMIAL = [
    r"^[a-z]+[a-z0-9]*[a-z0-9._-]*@example\.com$",
    r"^[a-z]+[a-z0-9]+[a-z0-9_]+[a-z0-9_-]+$",
    r"^[A-Za-z0-9]+[A-Za-z0-9_-]+[A-Za-z0-9]+$",
    r"[a-z]+[a-z0-9]+",
    r"\w+\w+",
    # an optional decoration between two repeats does not separate them: `_?` can match
    # empty, so this is the plain quadratic pattern with something in the middle.
    r"[a-z]+_?[a-z]+",
    r"[a-z]+[0-9]*[a-z]+",
    # anchors and lookarounds consume nothing, so they do not separate them either.
    r"[a-z]+\b[a-z]+",
]


@pytest.mark.parametrize("pattern", POLYNOMIAL)
def test_adjacent_repeats_over_overlapping_characters_are_refused_at_load(pattern):
    with pytest.raises(PolicyError, match="backtrack exponentially") as exc:
        Field(type="string", pattern=pattern)
    assert exc.value.code == "unsafe_pattern"


def test_the_refusal_says_the_repeats_can_match_the_same_character():
    """The message has to name the shape, because the author has to rewrite it."""
    with pytest.raises(PolicyError, match="two repeats in a row that can match the same character"):
        Field(type="string", pattern=r"^[A-Za-z0-9]+[A-Za-z0-9_-]+$")


# ── multi-character repeat bodies, which the first fix could not see ─────

# The overlap test only ever answered for a body that was one character wide; every
# multi-character body came back "do not know" and skipped the test entirely. So the same
# quadratic-or-worse shape, written as `(zz)+(zzz)+` instead of `z+z+`, loaded in 0.12 ms
# and then cost seconds per argument. Every entry here was measured by the auditor at
# between 0.4 s and >20 s on a single argument inside the real gate, and every one of them
# was accepted at load. The `\w` spellings of the same shapes were caught, which is the
# tell: nothing about them was harder to analyse, the analysis simply gave up.
MULTI_CHARACTER_BODIES = [
    r"^(?:zz)+(?:zzz)+(?:zzzzz)+$",
    r"^(xx)+(xxx)+(xxxxx)+(xxxxxxx)+$",
    r"^([b-d]{2})+([b-d]{3})+([b-d]{5})+([b-d]{7})+([b-d]{11})+$",
    r"^([b-d][b-d])+([b-d][b-d][b-d])+$",
    r"^(xy)+(yx)+$",
    r"^(..)+(...)+$",
]


@pytest.mark.parametrize("pattern", MULTI_CHARACTER_BODIES)
def test_a_multi_character_repeat_body_is_analysed_like_any_other(pattern):
    started = time.perf_counter()
    with pytest.raises(PolicyError, match="backtrack exponentially") as exc:
        Field(type="string", pattern=pattern)
    assert exc.value.code == "unsafe_pattern"
    assert time.perf_counter() - started < 1.0, "refused by shape, so it must not be timed"


def test_two_multi_character_bodies_that_cannot_share_a_boundary_still_load():
    """Only the *ends* of a body sit on the boundary between two repeats.

    `(?:ab)+(?:cd)+` has no ambiguity — a `c` says where the first run stopped — and a
    screen that intersected everything the two bodies contain would refuse it anyway.
    """
    assert Field(type="string", pattern=r"^(?:ab)+(?:cd)+$").pattern == r"^(?:ab)+(?:cd)+$"


def test_a_group_no_longer_hides_a_repeat_from_its_neighbour():
    """`([a-z]+)[a-z0-9]+` is `[a-z]+[a-z0-9]+` with one pair of parentheses.

    A group used to start a fresh adjacency analysis, so the two repeats were never
    compared and the pattern fell through to the timing probe — which decided it by wall
    clock and, under full-suite load, sometimes decided it the other way. The shape screen
    answers it now, which is both correct and the same answer every run.
    """
    started = time.perf_counter()
    with pytest.raises(PolicyError, match="two repeats in a row that can match the same character"):
        Field(type="string", pattern=r"([a-z]+)[a-z0-9]+")
    assert time.perf_counter() - started < 1.0


# ── a trailing `.`-repeat is not a clash ─────────────────────────────────

# `.` intersects almost every character class, so the overlap test refused any variable
# repeat that happened to be followed by `.*` or `.+`. That is a whole family of ordinary
# log-line and markdown rules, all measured at 0.0000 s on 4 KiB of adversarial input,
# refused for a blowup they cannot have: a greedy `.`-repeat at the end of the pattern
# swallows the remaining input on its first attempt and there is nothing after it to fail
# against, so no boundary between it and its neighbour ever has to move.
TRAILING_DOT_REPEAT = [
    r"^[a-z]+.*$",
    r"^\w+.+$",
    r"^\d+.*$",
    r"^(?:INFO|WARN)\s+.*$",
    r"^\s*[-*]\s+.+$",
    r"[a-z]+.*",  # unanchored, but `validate` uses `fullmatch`, so it is the same pattern
]


@pytest.mark.parametrize("pattern", TRAILING_DOT_REPEAT)
def test_a_trailing_dot_repeat_does_not_clash_with_what_precedes_it(pattern):
    assert Field(type="string", pattern=pattern).pattern == pattern


@pytest.mark.parametrize("pattern", TRAILING_DOT_REPEAT)
def test_a_trailing_dot_repeat_is_cheap_on_the_worst_input_it_admits(pattern):
    """The reason it is safe to allow, stated as a measurement rather than an argument.

    The genuinely worst case is not a mismatched byte — `.` matches those — but a newline,
    which `.` refuses and which therefore does make the boundary move. That costs about
    30 ms at the 4 KiB cap and is quadratic with a very small constant, against the 21 s
    the SQL-ish pattern below spends on the same length. Allowing it is the trade.
    """
    schema = Schema({"q": Field(type="string", pattern=pattern)})
    started = time.perf_counter()
    validate(schema, {"q": " -a" + "a" * (_MAX_PATTERN_INPUT - 4) + "\n"})
    assert time.perf_counter() - started < 1.0


def test_a_repeat_with_something_after_the_dot_repeat_is_still_a_clash():
    """The exemption is for *trailing* dots only — anything after it can still fail."""
    with pytest.raises(PolicyError, match="backtrack exponentially"):
        Field(type="string", pattern=r"^[a-z]+.*@example\.com$")


@pytest.mark.parametrize("pattern", [r"^.*.+$", r"^[^/]+[b-d]{3}?.*.+$"])
def test_a_dot_repeat_that_follows_another_dot_repeat_is_still_a_clash(pattern):
    """`.*.+` is one greedy run split two ways, and the exemption says nothing about it.

    Found by fuzzing the exemption: `^[^/]+[b-d]{3}?.*.+$` costs 39 s on 4 KiB of `d`
    followed by a newline. The argument for letting a trailing `.`-repeat through is that
    nothing after it can fail — which is true of the `.+`, and says nothing about the `.*`
    in front of it, whose boundary moves for every position in the input.
    """
    with pytest.raises(PolicyError, match="backtrack exponentially"):
        Field(type="string", pattern=pattern)


def test_the_sql_shaped_pattern_stays_refused():
    """A true positive, and the one the loosening above must not take with it.

    `[\\w,\\s*]+` and `\\s+` share every space character, and the auditor measured 20.98 s
    on one 4 KiB argument. It is refused for the same reason `[a-z]+[a-z0-9]+` is.
    """
    with pytest.raises(PolicyError, match="two repeats in a row that can match the same character"):
        Field(type="string", pattern=r"^SELECT\s+[\w,\s*]+\s+FROM\s+\w+$")


def test_the_headline_pattern_is_refused_before_it_can_ever_run():
    """Refusing at load is the whole point: `re` cannot be interrupted once matching.

    The pre-fix code accepted this in ~0.1 ms and then spent ~7.5 s inside the gate on
    a single 3200-character argument, with every other request in the process stopped.
    """
    started = time.perf_counter()
    with pytest.raises(PolicyError, match="backtrack exponentially"):
        Field(type="string", pattern=r"^[a-z]+[a-z0-9]*[a-z0-9._-]*@example\.com$")
    assert time.perf_counter() - started < 1.0


# ── the load-time probe, for what the shape screen cannot see ────────────

# The AST screen compares character sets, and an inline `(?i)` makes two disjoint-looking
# classes the same class. Only running the pattern catches that.
INVISIBLE_TO_THE_AST_SCREEN = [
    r"(?i)[a-z]+[A-Z]+",
    r"(?i)[a-z]+[A-Z]+[a-z]+[A-Z]+",
]


@pytest.mark.parametrize("pattern", INVISIBLE_TO_THE_AST_SCREEN)
def test_a_pattern_that_survives_the_shape_screen_is_still_timed_at_load(pattern):
    with pytest.raises(PolicyError, match="to reject a") as exc:
        Field(type="string", pattern=pattern)
    assert exc.value.code == "unsafe_pattern"


def test_the_probe_uses_the_patterns_own_alphabet_rather_than_a_fixed_one():
    """`(?i)[b-d]+[B-D]+` is `(?i)[a-z]+[A-Z]+` over three other letters.

    The probe used to build its inputs out of "a", "0", " " and "aA0_.-" — a list with no
    relation to the pattern in front of it. A pattern over `[b-d]` therefore matched none
    of the probe input, returned in 15 microseconds, and loaded. The filler now comes out
    of the pattern's own repeats, so the same shape gets the same answer whichever letters
    it is spelled with.
    """
    with pytest.raises(PolicyError, match="to reject a") as exc:
        Field(type="string", pattern=r"(?i)[b-d]+[B-D]+")
    assert exc.value.code == "unsafe_pattern"


@pytest.mark.parametrize(
    "pattern",
    [
        r"(?i)[a-z0-9]*x[a-z]*\w[a-z0-9]{1,4}",
        r"(?i)^[^\n]*?[b-d]{3}?(a|b)*?[A-Z]*$",
    ],
)
def test_the_filler_can_spell_the_parts_of_the_pattern_that_are_not_repeats(pattern):
    """A run has to get *past* the literals before the repeats around them can blow up.

    Drawing the filler from the variable repeats alone reproduced the original bug one
    level in: `x` and `[b-d]{3}` are not repeats, a filler of `a` fails in front of them,
    and the probe reports a fast pattern. Both of these were found by fuzzing; the second
    costs 96 s on 4 KiB of `b`.
    """
    # See above: several of these are now caught by the shape screen instead of the
    # probe, which is the better outcome — the assertion is that they are refused.
    with pytest.raises(PolicyError, match="refusing it"):
        Field(type="string", pattern=pattern)


def test_the_probe_ends_on_a_character_the_pattern_cannot_swallow():
    r"""A probe that matches measures nothing — the terminator has to force the failure.

    `[a-z]+?[A-Z]?[b-d]{2}[\w.-]*[^\n][\w.-]*` costs 79 s on 4 KiB of `b` ending in a
    newline, and nothing at all on the same input ending in `!`, because `[^\n]` and
    `[\w.-]*` between them absorb the `!`. Newline is the character `.`, `\w`, `\d` and
    most negated classes all refuse, which makes it the terminator to try first.
    """
    # Refused either way, and it is the shape screen that gets there first now: a leaf
    # both surrounding repeats can match no longer clears the adjacency list, so this
    # pair is caught at parse rather than by wall clock. Deterministic beats timed, so
    # the assertion is on the refusal rather than on which half produced it.
    with pytest.raises(PolicyError, match="refusing it"):
        Field(type="string", pattern=r"[a-z]+?[A-Z]?[b-d]{2}[\w.-]*[^\n][\w.-]*")


# Degree, written out. Each of these survives the shape screen — the classes really are
# disjoint in the parse tree — and each is polynomial of that degree once `(?i)` folds
# them together. They are here for what the *probe* costs, not for the verdict.
# The clock the probe itself picked, so the test bounds the same quantity the same way.
# Defining a second `thread_time` here reintroduced exactly what the code had just been
# fixed for: on Windows that clock is quantised to the 15.6 ms tick, so a run of 0.19 s
# reads as 0.203125 — thirteen ticks — and the assertion failed on the quantisation
# rather than on the code.
from histos.redos.probe import _cpu_clock as _cpu  # noqa: E402

# What one pattern may cost at load. The ladder is gated on what the previous two rungs
# cost, so a single pass lands near twice the budget; a verdict close enough to the
# budget that a busy machine could have invented it is measured a second time before it
# refuses, which doubles that again. Four is the guarantee.
#
# Asserted at six rather than four, because four is the *target* and a bound has to sit
# above the thing it bounds or it is a coin flip: a slow shared runner landed at 4.06x
# and went red on a ladder that was working exactly as designed. Six still fails loudly
# on the failure this test exists for — an unbounded ladder is 100x the budget and up,
# not 5x — while a rung costing twice what it should stays visible in the per-degree
# message.
_PER_PATTERN_BOUND = 6 * _PROBE_BUDGET_S

PROBE_TUNED = [
    (r"(?i)[a-z]+[A-Z]+", 2),
    (r"(?i)[a-z]+[A-Z]+[a-z]+[A-Z]+", 4),
    (r"(?i)[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+", 6),
    (r"(?i)[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+", 8),
    (r"(?i)" + r"[a-z]+[A-Z]+" * 6, 12),
]


@pytest.mark.parametrize(("pattern", "degree"), PROBE_TUNED, ids=lambda v: v if isinstance(v, int) else "")
def test_the_probe_is_bounded_by_its_own_budget_and_not_by_the_pattern(pattern, degree):
    """The probe cannot be interrupted either, so what it costs has to be bounded.

    The budget used to be checked only *between* probe runs, which bounded nothing: the
    run that blew it was already running. The ladder started at 64 characters, and a
    degree-8 pattern spends 45 seconds on its first probe at 64 — 900x the budget, inside
    `Field.__post_init__`, inside `contracts_from_mcp`, once per hostile tool in the
    manifest. The ladder now starts at 8, where nothing can be expensive, and each rung is
    gated on what the previous two cost, so a degree that projects past the budget is
    refused instead of measured. The bound is about twice the budget; the assertion is
    loose because the point is the order of magnitude, not the number.

    Measured in CPU burned by this thread, not in elapsed time. The quantity being
    bounded is GIL-held CPU — that is why the probe itself was changed to `thread_time`
    — and a wall clock on a shared CI runner measures the other tenants instead. These
    two assertions failed on three different jobs across three runs, never the same
    ones twice, which is what a test measuring the machine looks like.
    """
    started = _cpu()
    # See above: several of these are now caught by the shape screen instead of the
    # probe, which is the better outcome — the assertion is that they are refused.
    with pytest.raises(PolicyError, match="refusing it"):
        Field(type="string", pattern=pattern)
    elapsed = _cpu() - started
    assert elapsed < _PER_PATTERN_BOUND, f"degree {degree} cost {elapsed:.3f}s of load time"


def test_a_manifest_full_of_probe_tuned_patterns_does_not_add_up_to_a_hang():
    """N tools in one manifest multiply whatever a single load-time probe costs.

    Bounded as N times the per-pattern guarantee, which is the only bound the code
    actually offers. The old assertion was a flat `20 * budget` for twenty loads — an
    implied half a budget each, which nothing promises and which happened to hold only
    because most of these are refused by the shape screen before the probe runs. It sat
    at 738 ms of a 1 s bound on a fast laptop and went over on a CI runner, which is
    what an assertion calibrated to one machine does.
    """
    loads = PROBE_TUNED * 4
    started = _cpu()
    for pattern, _ in loads:
        with pytest.raises(PolicyError):
            Field(type="string", pattern=pattern)
    elapsed = _cpu() - started
    assert elapsed < len(loads) * _PER_PATTERN_BOUND, f"{len(loads)} loads cost {elapsed:.3f}s"


# ── the false-positive side: everything real must still load ─────────────

# Disjoint neighbours are unambiguous, so they stay legal — including the exact
# complements `\d`/`\D`, which a coarser overlap test would have refused.
BENIGN = [
    r"ORD-[0-9]+",
    r"[A-Za-z0-9._%+-]+@acme-corp\.com",
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"(v[0-9]+\.[0-9]+\.[0-9]+|[0-9a-f]{40})",
    r"^\d{4}-\d{2}-\d{2}$",
    r"^(GET|POST|PUT)$",
    r"\w+\s+\w+",
    r"(?>a+)+",
    r"a*+b",
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?",
    r"[a-z][a-z0-9-]{1,30}",
    r"PL[0-9]{26}",
    r"\d+\D+",
    r"\d+\W+",
    r"\S+\s\S+",
    r"[a-z]+[0-9]+[a-z]+",
    r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$",
    r"https?://[A-Za-z0-9.-]+/[A-Za-z0-9/_-]*",
    r"[一-鿿]+[0-9]+",
]


@pytest.mark.parametrize("pattern", BENIGN)
def test_the_screen_still_accepts_the_patterns_real_policies_use(pattern):
    assert Field(type="string", pattern=pattern).pattern == pattern


def _shipped_patterns() -> list[tuple[str, str]]:
    """Every `pattern:` in the published gallery and the demos, as (source, regex)."""
    sources = sorted((REPO / "policies").glob("*.policy.yaml")) + sorted((REPO / "demo").glob("*/security.policy.yaml"))
    found: list[tuple[str, str]] = []
    for src in sources:
        for match in re.finditer(r'pattern:\s*"((?:[^"\\]|\\.)*)"', src.read_text()):
            found.append((src.name, match.group(1).replace('\\"', '"')))
    return found


def test_every_pattern_the_repo_ships_still_loads():
    """A load-time refusal of a shipped policy is a worse outage than the ReDoS.

    Read straight out of the YAML rather than through the loader so this fails on the
    *pattern*, naming it, instead of on whichever policy happened to contain it.
    """
    shipped = _shipped_patterns()
    assert len(shipped) >= 15, "the extraction stopped finding patterns — fix the test, not the screen"
    for source, pattern in shipped:
        try:
            Field(type="string", pattern=pattern)
        except PolicyError as exc:
            pytest.fail(f"{source} ships {pattern!r} and the screen now refuses it: {exc}")


@pytest.mark.parametrize(
    "src",
    sorted((REPO / "policies").glob("*.policy.yaml")) + sorted((REPO / "demo").glob("*/security.policy.yaml")),
    ids=lambda p: p.parent.name + "/" + p.name,
)
def test_every_shipped_policy_still_loads_end_to_end(src: Path):
    assert load_policy(src).validate() == []


def test_loading_the_whole_gallery_stays_fast_despite_the_probe():
    """The probe runs per pattern at load, so it has to stay off the critical path."""
    started = time.perf_counter()
    for src in sorted((REPO / "policies").glob("*.policy.yaml")):
        load_policy(src)
    assert time.perf_counter() - started < 2.0


# ── the bound the module advertises is now a real bound ──────────────────


def test_a_permitted_pattern_stays_fast_on_a_full_length_worst_case():
    """What survives the screen has to be quick at the cap an argument can reach.

    Deliberately generous: the point is that a 4 KiB non-match is milliseconds rather
    than the 48 s the three-class identifier pattern used to take, not that it hits
    some particular microbenchmark.
    """
    permissive = [
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"https?://[A-Za-z0-9.-]+/[A-Za-z0-9/_-]*",
        r"\w+\s+\w+",
        r"[a-z]+[0-9]+[a-z]+",
    ]
    worst_case = "a" * (_MAX_PATTERN_INPUT - 1) + "!"

    started = time.perf_counter()
    for pattern in permissive:
        schema = Schema({"q": Field(type="string", pattern=pattern)})
        assert validate(schema, {"q": worst_case}) == ["q: does not match required pattern"]
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0, f"{len(permissive)} full-length non-matches took {elapsed:.3f}s"


# ── round three: two holes the last relaxation of this screen opened ──────


@pytest.mark.parametrize(
    "pattern",
    [
        r"^Q(?:[a-z]+){1,40}$",
        r"^[a-z]{1,4000}[a-z]{1,4000}$",
        r"^(?:[a-z]+){2,}$",
    ],
)
def test_a_finite_outer_bound_does_not_make_a_nested_repeat_safe(pattern):
    """`_unbounded` answered "is the outer repeat unbounded?", on the theory that a
    bounded one cannot produce runaway backtracking however ambiguous its body is. A
    finite bound caps the *exponent*, not the cost: `^Q(?:[a-z]+){1,40}$` passed and took
    17.5 seconds on 32 characters. The bound that matters is one iteration."""
    with pytest.raises(PolicyError, match="backtrack"):
        Field(type="string", pattern=pattern)


def test_a_repeat_that_runs_at_most_once_is_still_free():
    """`?` and `{0,1}` cannot split their input at all, which is what kept semver and
    the rest loading. The stricter rule must not take that back."""
    for pattern in (r"^\d+\.\d+\.\d+(?:-[\w.]+)?$", r"^(?:[a-z]+)?$", r"^(?:[a-z]+){1}$"):
        Field(type="string", pattern=pattern)


def test_a_pinned_field_does_not_erase_the_free_runs_around_it():
    """The separator held as `crossed` pins the boundary with the repeat that follows it
    — and only that boundary. Clearing the whole run threw away repeats it had never
    compared with anything: in `^.+,\\d+,.+,\\d+,.+$` each `\\d+` is pinned by its commas
    and wiped both `.+` runs to its left, so the three `.+` runs — all of which can
    absorb a comma — were never seen together. It loaded clean and cost 9.4 s at 4 KiB."""
    with pytest.raises(PolicyError, match="backtrack"):
        Field(type="string", pattern=r"^.+,\d+,.+,\d+,.+$")

    # Its two-run sibling is the one that must keep loading.
    Field(type="string", pattern=r"^.+,\d+$")


def test_a_must_consume_repeat_separates_only_what_it_is_disjoint_from():
    """`\\s` cannot be a `\\w`, so `\\w+\\s+\\w+` has a forced boundary and is not a pair
    of neighbours at all. `[^\\n]+` in `^.+,[^\\n]+,[^\\n]+$` consumes a character it
    could equally have left to either side, so it separates nothing."""
    Field(type="string", pattern=r"^\w+\s+\w+$")
    Field(type="string", pattern=r"^[a-z]+[0-9]+[a-z]+$")
    with pytest.raises(PolicyError, match="backtrack"):
        Field(type="string", pattern=r"^.+,[^\n]+,[^\n]+$")


def test_the_timing_probe_does_not_refuse_a_linear_pattern_on_a_busy_machine():
    """The probe compared wall-clock time against an absolute budget, so fifty
    descheduled `fullmatch` calls on a loaded CI runner added up to 50 ms of elapsed
    time while costing microseconds of CPU — and `ORD-[0-9]+`, a linear pattern with
    nothing wrong with it, was refused at policy-load time. A policy that loads on one
    worker and not on another is a coin toss, and the direction it lands is an outage.

    It measures CPU burned by this thread now, which is the quantity `re` actually holds
    the GIL for, and confirms a verdict before acting on it."""
    import threading
    import time

    stop = threading.Event()

    def burn() -> None:
        while not stop.is_set():
            pass

    threads = [threading.Thread(target=burn, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    try:
        time.sleep(0.2)
        for pattern in (r"ORD-[0-9]+", r"^\d{4}-\d{2}-\d{2}$", r"^[A-Z]{2}\d{6}$", r"^[a-z0-9_-]{3,32}$"):
            Field(type="string", pattern=pattern)
        # ...and the probe still refuses what it exists for, under the same load.
        with pytest.raises(PolicyError):
            Field(type="string", pattern=r"^(a+)+$")
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2)


def test_the_probe_refuses_a_clock_too_coarse_to_see_its_own_budget():
    """`thread_time` is the right quantity and on Windows it is `GetThreadTimes`, whose
    granularity is the ~15.6 ms system tick. Every small rung then reads exactly 0.0,
    the growth extrapolation that gates the next rung never fires, and the ladder climbs
    to 4 KiB on a pattern it should have refused at 64 characters — a degree-12 pattern
    costing 4 ms here cost 8.7 seconds there, inside `Field.__post_init__`, once per tool
    in the manifest. A self-bounding probe that cannot see its own budget is not bounded.
    """
    from histos.redos import probe as probe_module

    # Measured by spinning, not read from `time.get_clock_info` — which reports the
    # clock's *nominal* resolution and answers 100 ns for `thread_time` on Windows while
    # `GetThreadTimes` only advances on the scheduler tick. Reading that number is how
    # the first version of this check passed on Windows and changed nothing.
    tick = 0.015625
    origin = time.perf_counter()

    def windows_thread_time() -> float:  # advances only on the 15.6 ms tick
        return ((time.perf_counter() - origin) // tick) * tick

    # Two hundred trials, because asking only whether the clock *moved* inside the
    # window was a race: the 15.6 ms tick lands inside a 1 ms window about six times in
    # a hundred, so the selection came out fine-grained on some runs and coarse on
    # others and CI went green and red on the same commit. The step *size* answers it
    # whichever run observes it.
    assert not any(probe_module._granularity_under(windows_thread_time, _PROBE_BUDGET_S / 50) for _ in range(200))
    assert probe_module._granularity_under(time.perf_counter, _PROBE_BUDGET_S / 50)

    # Whichever clock gets picked, the property is the same one: it can resolve the
    # budget it is enforcing. Asserting `is time.thread_time` was asserting the platform
    # — right on Linux and macOS, wrong on Windows, where falling back is the correct
    # answer and the whole reason this selection exists.
    chosen = probe_module._probe_clock()
    assert probe_module._granularity_under(chosen, _PROBE_BUDGET_S / 50)
    assert chosen in (time.thread_time, time.perf_counter)


@pytest.mark.parametrize(("pattern", "degree"), PROBE_TUNED, ids=lambda v: v if isinstance(v, int) else "")
def test_the_ladder_stays_bounded_under_the_fallback_clock(pattern, degree):
    """The bound has to hold on the clock Windows will actually use."""
    from histos.redos import probe as probe_module

    kept = probe_module._cpu_clock
    probe_module._cpu_clock = time.perf_counter
    try:
        started = time.perf_counter()
        with pytest.raises(PolicyError):
            Field(type="string", pattern=pattern)
        elapsed = time.perf_counter() - started
    finally:
        probe_module._cpu_clock = kept
    assert elapsed < _PER_PATTERN_BOUND, f"degree {degree} cost {elapsed:.3f}s under perf_counter"


def test_a_separator_may_be_a_class_and_not_only_a_literal():
    """`_anchored_body`/`_terminated_body` insisted on a bare `LITERAL`, so the
    single-delimiter spelling of a shape loaded and the two-delimiter spelling of the
    same shape was refused. The test that matters is disjointness from the rest of the
    body, and `[-_]` answers it exactly as `-` does. All four measure 0.0 ms."""
    for pattern in (
        r"^(?:[a-z]+-){2,4}$",
        r"^(?:[a-z]+[-_]){2,4}$",
        r"^(?:[a-z]+[.:]){2,6}$",
        r"^(?:\w+[/\\]){1,8}$",
    ):
        Field(type="string", pattern=pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^(?:[a-z]+){2,}$",  # no separator at all
        r"^(?:[a-z]*-)*[a-z]*$",  # a body that can shrink to just the separator
        r"^(a+)+$",
        r"^(?:[a-z]+|[a-z]+x){2,4}$",  # an alternation, not a fixed-width separator
    ],
)
def test_widening_the_separator_admits_none_of_the_bombs(pattern):
    """The excuse is only ever safe because the separator is one character the rest of
    the body cannot produce. Widening what counts as that character must not widen what
    counts as a separator."""
    with pytest.raises(PolicyError):
        Field(type="string", pattern=pattern)


@pytest.mark.parametrize(
    "cap,runs,verdict",
    [
        # The table this rule was originally set from, measured under `re.fullmatch` on
        # 4 KiB of the pattern's own alphabet failing at the last character:
        #
        #     max=  64   2 runs 0.0 ms   3 runs   1.4 ms   4 runs      88 ms
        #     max= 512   2 runs 1.3 ms   3 runs   656 ms   4 runs  13 226 ms
        #     max=4096   2 runs 39  ms   3 runs 6 645 ms   (identical to unbounded)
        #
        # The first reading of it was "a finite bound does not stop a run accumulating a
        # degree, so refuse every adjacent pair". That reads the rows down the wrong axis:
        # what separates 0.0 ms from 13 seconds is not how many repeats there are, it is
        # the *product* of their caps — the number of ways the run can split its input.
        # The threshold below is set from that product, and it reproduces every verdict
        # this table asks for, which counting did not.
        (64, 2, "load"),  # 4 096 splits, 0.0 ms
        (64, 3, "load"),  # 262 144, 1.4 ms
        (64, 4, "refuse"),  # 16.7 M, 88 ms
        (512, 2, "load"),  # 262 144, 1.3 ms
        (512, 3, "refuse"),  # 134 M, 656 ms
        (512, 4, "refuse"),  # 68.7 G, 13.2 s
        (4096, 2, "refuse"),  # 16.7 M, 39 ms — a bound at the argument cap is not a bound
        (4096, 3, "refuse"),  # 68.7 G, 6.6 s
    ],
)
def test_the_cost_of_an_adjacent_run_is_its_product_not_its_length(cap, runs, verdict):
    pattern = "^" + f"[a-z]{{1,{cap}}}" * runs + "$"
    if verdict == "refuse":
        with pytest.raises(PolicyError, match="backtrack"):
            Field(type="string", pattern=pattern)
    else:
        Field(type="string", pattern=pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[a-zA-Z]{1,10}[a-zA-Z0-9]{0,20}$",  # a username validator — 200 splits, 0.00 ms
        r"^\w{1,64}\w{1,64}$",  # 4 096 splits, 0.03 ms
        r"^[a-z]{1,100}[a-z0-9]{1,100}$",  # 10 000 splits, 0.05 ms
        r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}[A-Z0-9]{0,16}$",  # IBAN
    ],
)
def test_an_ordinary_bounded_validator_is_not_refused(pattern):
    """Counting adjacent repeats refused these, and refusing them buys nothing.

    The username shape is the one that mattered: `sources_from_mcp` skips a tool whose
    pattern will not load, so an MCP server shipping the most ordinary validator there
    is lost the tool at import — a control silently removing the thing it protects.
    """
    Field(type="string", pattern=pattern)


def test_the_single_repeat_spelling_an_author_means_is_still_fine():
    Field(type="string", pattern=r"^[a-z]{2,6}$")
