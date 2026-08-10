"""In-process rate and budget counters.

Two limits per (principal, tool):

* **rate_limit** — at most N calls per rolling ``window_seconds``.
* **budget** — at most N calls total, for the life of this process/store.

**Statefulness caveat:** this state is *in-process*. For a single
process (the pilot target) that is correct and needs no infra. Across processes
or replicas it would need shared state — the same limitation any in-memory
limiter has. We surface the caveat rather than pretend it is free.

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

    def _key(self, identity: str | None, tool: str) -> tuple[str, str]:
        return (identity or "<anonymous>", tool)

    def check(self, identity: str | None, tool: str, *, rate_limit: int | None, budget: int | None) -> str | None:
        """Return a rule name if a limit would be exceeded, else ``None`` (read-only).

        Advisory only — use :meth:`try_consume` for enforcement, since a separate
        ``check`` then ``consume`` is not atomic across concurrent callers.
        """
        with self._lock:
            return self._check_locked(self._key(identity, tool), rate_limit, budget)

    def consume(self, identity: str | None, tool: str) -> None:
        """Record one allowed call against both the rate window and the budget."""
        with self._lock:
            self._consume_locked(self._key(identity, tool))

    def try_consume(self, identity: str | None, tool: str, *, rate_limit: int | None, budget: int | None) -> str | None:
        """Atomically check limits and, if within them, consume one slot.

        Returns the exceeded rule name (``"rate_limit"``/``"budget"``) without
        consuming, or ``None`` after consuming. This is the enforcement path.
        """
        with self._lock:
            key = self._key(identity, tool)
            rule = self._check_locked(key, rate_limit, budget)
            if rule is None:
                self._consume_locked(key)
            return rule

    def _check_locked(self, key: tuple[str, str], rate_limit: int | None, budget: int | None) -> str | None:
        if budget is not None and self._budget_used[key] >= budget:
            return "budget"
        if rate_limit is not None and self._recent_count(key) >= rate_limit:
            return "rate_limit"
        return None

    def _consume_locked(self, key: tuple[str, str]) -> None:
        self._calls[key].append(self._now())
        self._budget_used[key] += 1

    def _recent_count(self, key: tuple[str, str]) -> int:
        now = self._now()
        window = self._calls[key]
        cutoff = now - self._window
        while window and window[0] < cutoff:
            window.popleft()
        return len(window)
