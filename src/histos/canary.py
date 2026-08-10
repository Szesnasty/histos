"""Exact-match canary detection.

A canary is a unique token the developer plants (in a system prompt, a fake
secret, a honeypot record). If it appears **verbatim** in a tool argument
(exfiltration attempt, caught pre-gate) or in a tool output (leak, caught
post-gate), the gate reacts.

**Exact match only, by design**. This catches
verbatim leakage — a real, common, high-value case (system-prompt leak, planted
-secret echo). It deliberately does NOT catch *transformed* exfiltration
(base64, split across calls, paraphrase); that is the semantic tier. Keeping it
exact is what makes it deterministic and non-interpretive.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable

# A fixed, documented normalization set (Phase 0.1). Zero-width / invisible chars…
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}
# …and a closed separator set, stripped so a spaced-out token still matches.
_SEPARATORS = set(" \t\r\n-_.·•|,")


def find(text: str, tokens: Iterable[str]) -> list[str]:
    """Canary tokens that appear verbatim in ``text`` (deduped, order-stable)."""
    if not text:
        return []
    found: list[str] = []
    for tok in tokens:
        if tok and tok in text and tok not in found:
            found.append(tok)
    return found


def normalize_for_match(text: str) -> str:
    """Fixed, symmetric normalization so ``A K I A-1234`` still matches ``AKIA1234``.

    NFKC → drop zero-width → drop a closed separator set → casefold. Applied
    identically to the scanned text AND to each token (fold them differently and you
    introduce silent misses). Deliberately narrow — it catches simple mechanical
    transforms, not base64/paraphrase (that is the semantic tier).
    """
    s = unicodedata.normalize("NFKC", text)
    s = "".join(ch for ch in s if ch not in _ZERO_WIDTH and ch not in _SEPARATORS)
    return s.casefold()


def find_normalized(text: str, tokens: Iterable[str]) -> list[str]:
    """Canary tokens present in ``text`` after :func:`normalize_for_match` (deduped)."""
    if not text:
        return []
    norm_text = normalize_for_match(text)
    found: list[str] = []
    for tok in tokens:
        norm_tok = normalize_for_match(tok) if tok else ""
        if norm_tok and norm_tok in norm_text and tok not in found:
            found.append(tok)
    return found


def redact(text: str, tokens: Iterable[str], *, mark: str = "[REDACTED-CANARY]") -> tuple[str, list[str]]:
    """Replace every verbatim canary token in ``text`` with ``mark``.

    Returns ``(redacted_text, tokens_found)``.
    """
    found: list[str] = []
    out = text
    # Redact longer tokens first: if one canary is a substring of another, replacing
    # the shorter one first would mangle the longer token before it can be matched.
    for tok in sorted(tokens, key=len, reverse=True):
        if tok and tok in out:
            if tok not in found:
                found.append(tok)
            out = out.replace(tok, mark)
    return out, found
