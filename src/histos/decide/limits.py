"""In-process rate and budget counters.

Two limits per (principal, tool):

* **rate_limit** — at most N calls per rolling ``window_seconds``.
* **budget** — at most N calls total, for the life of this process/store.

**Statefulness caveat:** this state is *in-process*. For a single
process (the pilot target) that is correct and needs no infra. Across processes
or replicas it would need shared state — the same limitation any in-memory
limiter has. We surface the caveat rather than pretend it is free.

**Growth:** only the *enforcement* path allocates, and only for a key that has
actually consumed a slot — checking a limit for a thousand identities leaves
nothing behind. Rate state that has fallen out of the window is dropped by
:meth:`LimitStore.prune`, which a long-lived host should call periodically; budget
counters are permanent by definition and are never pruned.

The clock is injectable so limit behaviour is deterministic under test.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class LimitStore:
    """Tracks call rates and budgets keyed by ``(identity, tool)``.

    Thread-safe: all mutating paths hold ``_lock``, and :meth:`try_consume`
    performs the check-and-consume **atomically** so concurrent calls of the same
    (identity, tool) cannot both slip past a limit (no check→consume TOCTOU).
    """

    def __init__(self, *, window_seconds: float = 60.0, time_fn: Callable[[], float] = time.monotonic) -> None:
        self._window = window_seconds
        self._now = time_fn
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._budget_used: dict[tuple[str, str], int] = defaultdict(int)
        self._lock = threading.RLock()

    @property
    def window_seconds(self) -> float:
        """The rolling window every ``rate_limit`` in the policy is counted against.

        One window per store, not per tool, and it is not in the policy format — so
        `rate_limit: 3` in a document means "3 per *this* many seconds" and the document
        cannot say how many. Readable here, and named in the denial, until the format
        carries it (see docs/roadmap.md, `limit_scope`).
        """
        return self._window

    def _key(self, identity: str | None, tool: str) -> tuple[str, str]:
        return (identity or "<anonymous>", tool)

    def check(self, identity: str | None, tool: str, *, rate_limit: int | None, budget: int | None) -> str | None:
        """Return a rule name if a limit would be exceeded, else ``None``.

        Genuinely read-only: it allocates nothing and prunes nothing, so evaluating a
        policy for analysis (``histos explain``, a change-impact replay) does not
        perturb the store it is measuring. It used to allocate a deque per key, which
        made ``Engine.pre`` — documented as pure — grow without bound under an
        attacker-chosen identity string.

        Advisory only — use :meth:`try_consume` for enforcement, since a separate
        ``check`` then ``consume`` is not atomic across concurrent callers.
        """
        with self._lock:
            return self._check_locked(self._key(identity, tool), rate_limit, budget)

    def consume(self, identity: str | None, tool: str, *, rate_limit: int | None = 1, budget: int | None = 1) -> None:
        """Record one allowed call against the rate window and the budget.

        The limits are passed so nothing is recorded for a limit the contract does not
        declare; the defaults keep the bare ``consume(identity, tool)`` spelling meaning
        "record against both", which is what a caller reaching for it expects.
        """
        with self._lock:
            self._consume_locked(self._key(identity, tool), rate_limit, budget)

    def try_consume(self, identity: str | None, tool: str, *, rate_limit: int | None, budget: int | None) -> str | None:
        """Atomically check limits and, if within them, consume one slot.

        Returns the exceeded rule name (``"rate_limit"``/``"budget"``) without
        consuming, or ``None`` after consuming. This is the enforcement path.
        """
        with self._lock:
            key = self._key(identity, tool)
            rule = self._check_locked(key, rate_limit, budget)
            if rule is None:
                self._consume_locked(key, rate_limit, budget)
            return rule

    def prune(self) -> int:
        """Drop rate state that has fallen out of the window; return how many keys went.

        A budget is by definition for the life of the store, so budget counters are
        never pruned — forgetting one would hand the caller its allowance back. Rate
        state is different: once the window has passed, the entry says nothing that a
        missing entry does not, so keeping it is pure growth. Call this from whatever
        already runs periodically; nothing here calls it for you, because a limiter
        that decides on its own when to forget is a limiter you cannot reason about.
        """
        with self._lock:
            cutoff = self._now() - self._window
            stale = [key for key, window in self._calls.items() if not window or window[-1] < cutoff]
            for key in stale:
                del self._calls[key]
            return len(stale)

    def _check_locked(self, key: tuple[str, str], rate_limit: int | None, budget: int | None) -> str | None:
        if budget is not None and self._budget_used.get(key, 0) >= budget:
            return "budget"
        if rate_limit is not None and self._recent_count(key) >= rate_limit:
            return "rate_limit"
        return None

    def _consume_locked(self, key: tuple[str, str], rate_limit: int | None, budget: int | None) -> None:
        # Only what a declared limit can read. Every allowed call used to write both a
        # deque and a budget counter for every (identity, tool) pair, and budget
        # counters are never pruned by design — so a tool with no `budget:` at all
        # accumulated one permanent entry per identity that had ever called it, which
        # on a multi-tenant server is unbounded growth `prune()` cannot reclaim and
        # nothing reads.
        if rate_limit is not None:
            window = self._calls[key]
            window.append(self._now())
            # Prune where the state is already being written, so the deque for one key
            # cannot outgrow its window even if `prune()` is never called.
            cutoff = self._now() - self._window
            while window and window[0] < cutoff:
                window.popleft()
        if budget is not None:
            self._budget_used[key] += 1

    def _recent_count(self, key: tuple[str, str]) -> int:
        """Calls inside the window, without allocating or mutating anything.

        Expired entries are skipped rather than popped: this runs on the read path,
        and a read that edits the store is not a read.
        """
        window = self._calls.get(key)
        if not window:
            return 0
        cutoff = self._now() - self._window
        return sum(1 for at in window if at >= cutoff)
