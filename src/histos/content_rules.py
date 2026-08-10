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

from histos import patterns


@dataclass(frozen=True)
class ContentRules:
    """Opt-in static argument scanning. Both checks default on *once enabled*."""

    check_injection: bool = True
    check_exfiltration: bool = True

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
