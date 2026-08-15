"""Optional, opt-in deterministic content rules — NOT part of the core gate.

Review point #3: regex "prompt-injection detection" is a *heuristic*. It has
false positives and trivial bypasses, and keeping it in the authorization core
blurs the crisp line the product should own:

    the gate does not detect injection — it bounds what the agent can do.

So these static pattern checks live here, **off by default**, and are wired in
only if the developer explicitly opts in (``Gate(content_rules=ContentRules())``).
They are deterministic (exact regex, not model interpretation), so they are still
legitimately in-process — but they are a *content-hygiene* add-on, not the
foundation. The canary check (exact-match) stays in the core; it is not a
heuristic.
"""

from __future__ import annotations

from dataclasses import dataclass

from histos.decide import patterns
from histos.errors import PolicyError


@dataclass(frozen=True)
class ContentRules:
    """Opt-in static argument scanning. Both checks default on *once enabled*."""

    check_injection: bool = True
    check_exfiltration: bool = True

    def __post_init__(self) -> None:
        for name in ("check_injection", "check_exfiltration"):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise PolicyError(f"{name} must be true or false, got {value!r}")

    def scan(self, text: str) -> tuple[str, str] | None:
        """Return ``(rule, matched_pattern)`` for the first hit, or ``None``."""
        if not text:
            return None
        scan_text = text[: patterns._MAX_SCAN_LEN]
        if self.check_injection:
            for pat in patterns.INJECTION_PATTERNS:
                if pat.search(scan_text):
                    return ("injection_pattern", pat.pattern)
        if self.check_exfiltration:
            for pat in patterns.EXFILTRATION_PATTERNS:
                if pat.search(scan_text):
                    return ("exfiltration_pattern", pat.pattern)
        return None
