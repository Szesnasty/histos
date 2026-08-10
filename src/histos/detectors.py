"""Structured secret detectors (Phase 0.1) — checksum + structural, with confidence.

Deterministic, high-precision recognition of *known-format* secrets in string
values, used two ways:

* **PRE, `on_arg`** — a hijacked-but-authorized agent putting a real credential
  into a validly-typed argument is denied (default: only ``checksum``-confidence
  hits deny, so a structural false positive cannot block a legitimate call).
* **POST, `on_output`** — the same detectors redact a credential a backend leaked
  into a tool result before it reaches the model.

**Two confidence classes, kept honest (review):**

* ``checksum`` — cryptographic/algorithmic verification: PAN (Luhn + length),
  IBAN (mod-97), a JWT that actually *decodes* to a JSON header with an ``alg``.
* ``structural`` — prefix/shape recognition only (AWS ``AKIA``/``ASIA``, GitHub
  ``ghp_``, Slack ``xox…``, Stripe ``sk_live_``, PEM key headers). High-signal but
  **not** cryptographically confirmed — so it defaults to *redact/flag*, not deny.

**Residual (honest):** recall is bounded to the enumerated formats — an unknown or
rotated credential is invisible; matches are SHAPE, not PROVENANCE (a planted fake
key trips it → per-tool opt-out); a secret split across arguments defeats the
checksum. Free-text / paraphrased / encoded secrets are the semantic tier's job.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

CHECKSUM = "checksum"
STRUCTURAL = "structural"

REDACTION_MARK = "[REDACTED-SECRET]"


@dataclass(frozen=True)
class Detection:
    kind: str  # e.g. "pan", "iban", "aws_key", "jwt"
    confidence: str  # CHECKSUM | STRUCTURAL
    start: int
    end: int


# ── checksums ────────────────────────────────────────────────────────────


def luhn_ok(digits: str) -> bool:
    """Luhn (mod-10) check over a run of digits."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(candidate: str) -> bool:
    """IBAN mod-97-10 check (ISO 13616)."""
    s = candidate.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _jwt_decodes(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        head = parts[0]
        head += "=" * (-len(head) % 4)
        payload = json.loads(base64.urlsafe_b64decode(head.encode("ascii")))
    except (ValueError, TypeError):
        return False
    return isinstance(payload, dict) and "alg" in payload


# ── structural patterns ──────────────────────────────────────────────────

# A PEM detection must span the whole armoured block, not the header. Matching the
# recognisable prefix alone made redaction *worse than absent*: the header vanished,
# every line of key material egressed, and the audit record asserted
# `secret:pem_private_key` had been removed. The label is left open (`RSA`, `EC`,
# `OPENSSH`, `ENCRYPTED`, `PGP … BLOCK`, anything future) because an unrecognised
# label must still redact, and a missing END marker falls through to end-of-string —
# a truncated key is still a key.
_PEM_LABEL = r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?"
_PEM_BLOCK = rf"-----BEGIN {_PEM_LABEL}-----(?s:.*?)(?:-----END {_PEM_LABEL}-----|\Z)"

_STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[opusr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("pem_private_key", re.compile(_PEM_BLOCK)),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
]

# Candidate runs for the checksum detectors (validated before a Detection is emitted).
_DIGIT_RUN = re.compile(r"\b[0-9][0-9 -]{11,21}[0-9]\b")
_IBAN_RUN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_JWT_RUN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def scan_string(text: str) -> list[Detection]:
    """All secret detections in ``text``, checksum-verified where possible."""
    found: list[Detection] = []

    for m in _DIGIT_RUN.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if luhn_ok(digits):
            found.append(Detection("pan", CHECKSUM, m.start(), m.end()))

    for m in _IBAN_RUN.finditer(text):
        if iban_ok(m.group()):
            found.append(Detection("iban", CHECKSUM, m.start(), m.end()))

    for m in _JWT_RUN.finditer(text):
        if _jwt_decodes(m.group()):
            found.append(Detection("jwt", CHECKSUM, m.start(), m.end()))

    for kind, pattern in _STRUCTURAL_PATTERNS:
        for m in pattern.finditer(text):
            found.append(Detection(kind, STRUCTURAL, m.start(), m.end()))

    return found


def redact_string(text: str, *, mark: str = REDACTION_MARK) -> tuple[str, list[str]]:
    """Replace every detected secret span with ``mark`` (both confidence classes).

    Returns ``(redacted_text, kinds_found)``. Overlapping spans are merged into
    their union and replaced right-to-left so indices stay valid.

    Overlaps are merged rather than skipped because skipping dropped the *enclosing*
    span: a Slack token whose digit run happens to be Luhn-valid was detected as both
    `slack_token` and `pan`, the inner `pan` was redacted first, and the guard then
    discarded the wider span — so the token's prefix and secret tail both egressed and
    the audit trail named only `pan`. Every detected kind is reported, including one
    subsumed by a wider span, so `redact_string` and `scan_string` (which the pre-gate
    denies on) can never disagree about what was found.
    """
    dets = scan_string(text)
    if not dets:
        return text, []
    # Widest span first at a given start, so a cluster merges into its enclosing span.
    dets_sorted = sorted(dets, key=lambda d: (d.start, -d.end))
    clusters: list[tuple[int, int, list[str]]] = []
    for d in dets_sorted:
        if clusters and d.start < clusters[-1][1]:
            start, end, kinds_here = clusters[-1]
            clusters[-1] = (start, max(end, d.end), [*kinds_here, d.kind])
        else:
            clusters.append((d.start, d.end, [d.kind]))

    out = text
    for start, end, _kinds in reversed(clusters):
        out = out[:start] + mark + out[end:]
    return out, [kind for _s, _e, kinds_here in clusters for kind in kinds_here]
