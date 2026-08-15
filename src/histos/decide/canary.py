"""Canary detection — verbatim, plus one fixed normalization.

A canary is a unique token the developer plants (in a system prompt, a fake
secret, a honeypot record). If it appears in a tool argument (exfiltration
attempt, caught pre-gate) or in a tool output (leak, caught post-gate), the gate
reacts.

Matching is **mechanical, not semantic**, in two tiers applied on *both* sides of
the gate: verbatim, and after :func:`normalize_for_match` — a fixed, closed
transform (NFKC → drop zero-width → drop a closed separator set → casefold) so
``C A N A R Y-7f3a`` and a token with a zero-width space wedged into it still
match. It deliberately does NOT catch *transformed* exfiltration (base64, split
across calls, paraphrase); that is the semantic tier. Keeping the transform fixed
and closed is what makes it deterministic and non-interpretive.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable

DEFAULT_MARK = "[REDACTED-CANARY]"

# A fixed, documented normalization set (Phase 0.1). Zero-width / invisible chars…
_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
# …and a closed separator set, stripped so a spaced-out token still matches.
_SEPARATORS = set(" \t\r\n-_.·•|,")
# One prebuilt deletion table for both sets: str.translate runs in C, while the
# per-character genexpr it replaces cost ~300 ms per megabyte of arguments and made
# a schema-valid call with a large array a CPU stall inside a fail-closed gate.
_STRIP_TABLE = dict.fromkeys(ord(ch) for ch in _ZERO_WIDTH | _SEPARATORS)

# Above this, a normalized-only hit stops being located span-by-span (the index map
# below is a per-character Python loop) and the whole value is dropped instead.
# Bounding the work is not optional here: this runs on attacker-influenceable text.
_MAX_MAPPED_CHARS = 65_536


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
    return unicodedata.normalize("NFKC", text).translate(_STRIP_TABLE).casefold()


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


def redact(text: str, tokens: Iterable[str], *, mark: str = DEFAULT_MARK) -> tuple[str, list[str]]:
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


def _normalized_with_index(text: str) -> tuple[str, list[int]]:
    """:func:`normalize_for_match`, but per character, keeping each result char's
    index in the ORIGINAL string so a normalized match can be located back in it.

    Per-character NFKC cannot compose across characters the way the whole-string
    form does, so this is *weaker* than :func:`normalize_for_match` and is only ever
    used to locate a hit that function already made. Callers verify afterwards and
    drop the whole value if anything still matches — never the other way round.
    """
    chars: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        for nch in unicodedata.normalize("NFKC", ch):
            if nch in _ZERO_WIDTH or nch in _SEPARATORS:
                continue
            for folded in nch.casefold():  # casefold can expand (ß → ss)
                chars.append(folded)
                origin.append(i)
    return "".join(chars), origin


def _redact_spans(text: str, tokens: Iterable[str], mark: str) -> str:
    norm, origin = _normalized_with_index(text)
    spans: list[tuple[int, int]] = []
    for tok in tokens:
        norm_tok = normalize_for_match(tok) if tok else ""
        if not norm_tok:
            continue
        pos = norm.find(norm_tok)
        while pos >= 0:
            spans.append((origin[pos], origin[pos + len(norm_tok) - 1] + 1))
            pos = norm.find(norm_tok, pos + 1)
    if not spans:
        return text
    # Merge overlapping spans (two canaries can share characters once separators are
    # stripped) so replacing right-to-left cannot cut a span that was already cut.
    spans.sort()
    merged: list[list[int]] = [list(spans[0])]
    for start, end in spans[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out = text
    for start, end in reversed(merged):
        out = out[:start] + mark + out[end:]
    return out


def redact_normalized(text: str, tokens: Iterable[str], *, mark: str = DEFAULT_MARK) -> tuple[str, list[str]]:
    """Replace canary tokens that only appear after :func:`normalize_for_match`.

    The pre-gate has always matched normalized, so a zero-width space or a spaced-out
    token is caught on the way *in*; the post-gate matched verbatim only, which made
    the output channel the cheap way around the control — one zero-width space and the
    same token egressed under an ALLOW. Post now matches at least as hard as pre.

    Fail-closed by construction: locating the span is best-effort, so the result is
    re-checked and the entire value is dropped if any normalized hit survives.
    """
    found = find_normalized(text, tokens)
    if not found:
        return text, []
    if len(text) > _MAX_MAPPED_CHARS:
        return mark, found
    out = _redact_spans(text, found, mark)
    if find_normalized(out, found):
        return mark, found
    return out, found
