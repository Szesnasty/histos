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

from histos.decide.canary import _INVISIBLE

CHECKSUM = "checksum"
STRUCTURAL = "structural"

REDACTION_MARK = "[REDACTED-SECRET]"

# The same set the canary scan strips, for the same reason and from the same place: one
# definition of "invisible", so the two controls on one piece of text cannot disagree
# about what is in it. See `histos.decide.canary`.
_INVISIBLE_TABLE = dict.fromkeys(ord(ch) for ch in _INVISIBLE)

# The canary module's bound, for the identical per-character index map. Above it a hit is
# reported spanning the whole text rather than located.
_MAX_MAPPED_CHARS = 65_536


@dataclass(frozen=True)
class Detection:
    kind: str  # e.g. "pan", "iban", "aws_key", "jwt"
    confidence: str  # CHECKSUM | STRUCTURAL
    start: int
    end: int


# ── checksums ────────────────────────────────────────────────────────────


# The (prefix, length) combinations the card schemes actually issue. Luhn on its own
# is a mod-10 checksum, which one number in ten passes by chance — so "13-19 digits and
# Luhn-clean" also describes about 10% of every order number, meter reading, serial and
# account reference a tool legitimately returns, and 100% of IMEIs, which are 15 digits
# and Luhn by specification. Redacting those is not a conservative call: the tool
# silently stops working and the audit record asserts a card number was removed. A real
# PAN always carries an issuer prefix, so requiring one costs nothing against real cards
# and removes the bulk of the false positives.
# The scheme-published (prefix, accepted lengths) table. The first version of it was
# written from the brands somebody could name, which lost Maestro entirely — a whole
# scheme, not an edge case — and Discover's 19-digit form. A miss here is a card number
# that egresses, which is the direction that matters, so the table is checked against
# `tests/corpus/cards.json`: numbers whose check digit is computed from these prefixes
# rather than remembered, precisely so the corpus cannot inherit the same blind spot.
_PAN_PREFIXES: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("4", (13, 16, 19)),  # Visa
    *((str(n), (16,)) for n in range(51, 56)),  # Mastercard
    *((str(n), (16,)) for n in range(2221, 2721)),  # Mastercard 2-series
    ("34", (15,)),
    ("37", (15,)),  # Amex
    ("6011", (16, 19)),
    ("65", (16, 19)),  # Discover
    *((str(n), (16, 19)) for n in range(644, 650)),  # Discover
    ("36", (14,)),  # Diners
    *((str(n), (14,)) for n in range(300, 306)),  # Diners
    ("3095", (14,)),
    ("38", (14,)),
    ("39", (14,)),  # Diners
    *((str(n), (16, 19)) for n in range(3528, 3590)),  # JCB
    ("62", (16, 17, 18, 19)),  # UnionPay
    # Maestro. Variable length by design (12-19), which is why it was the one that fell
    # out of a table built around "16 digits, sometimes 15".
    *((p, tuple(range(12, 20))) for p in ("5018", "5020", "5038", "5893", "6304", "6759", "6761", "6762", "6763")),
)

# Sorted longest-first and grouped by first digit, so a lookup is a handful of
# comparisons rather than a walk of the whole table. It runs per Luhn-clean digit run in
# every scanned output, and the flat version was a 589-entry linear scan.
_PAN_BY_FIRST: dict[str, tuple[tuple[str, tuple[int, ...]], ...]] = {}
for _prefix, _lengths in _PAN_PREFIXES:
    _PAN_BY_FIRST.setdefault(_prefix[0], ())
for _first in _PAN_BY_FIRST:
    _PAN_BY_FIRST[_first] = tuple(sorted((p, ln) for p, ln in _PAN_PREFIXES if p[0] == _first))
del _prefix, _lengths, _first


def looks_like_a_pan(digits: str) -> bool:
    """Whether a Luhn-clean run also carries an issuer prefix and a length to match.

    Luhn alone is a mod-10 checksum that one number in ten passes by chance, so it also
    describes ~10% of order numbers and serials and 100% of IMEIs, which are 15 digits
    and Luhn by specification. A real PAN always carries an issuer prefix, and requiring
    one costs nothing against real cards — provided the table is complete, which is the
    failure mode in the other direction.
    """
    if not digits:
        return False
    length = len(digits)
    return any(digits.startswith(prefix) and length in lengths for prefix, lengths in _PAN_BY_FIRST.get(digits[0], ()))


def luhn_ok(digits: str) -> bool:
    """Luhn (mod-10) check over a run of digits."""
    # 12, not 13. The PAN table was widened for Maestro with `range(12, 20)` and the
    # comment "variable length by design (12-19)", and the two length gates in front of
    # it were not widened with it — so the shortest Maestro that exists could never
    # reach the table and egressed unredacted.
    if not digits.isdigit() or not (12 <= len(digits) <= 19):
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
_DIGIT_RUN = re.compile(r"\b[0-9][0-9 -]{10,21}[0-9]\b")  # 12 digits at the short end; see `luhn_ok`
_IBAN_RUN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_JWT_RUN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def scan_string(text: str) -> list[Detection]:
    """All secret detections in ``text``, checksum-verified where possible.

    Read twice when it has to be: once as it came, and once with every Unicode format
    character removed. The canary scan beside this one has normalised since the second
    adversarial pass; these patterns matched the text as written, so a single invisible
    character split every one of them. `deny_secret_args` is on by default and refuses a
    checksum-confidence secret in an argument — and one soft hyphen walked a card number
    straight into the tool, for all 170 spellings of "invisible".

    Only Cf characters are removed, and deliberately not the separators the canary
    normalisation also drops. A format character has no business inside a PAN, an IBAN or
    a JWT, so deleting it invents no match; deleting `.` or `_` would splice two adjacent
    honest values into a third that checksums by chance, and this scan denies calls.
    """
    found = _scan_verbatim(text)
    stripped = text.translate(_INVISIBLE_TABLE)
    if len(stripped) == len(text):
        return found  # nothing invisible in it, so there is no second reading
    return _merge(found, _relocated(text, stripped))


def _relocated(text: str, stripped: str) -> list[Detection]:
    """Detections in the invisible-stripped text, with spans back in the original.

    The span has to cover the format characters interleaved through the secret, or
    redaction would leave their fragments behind. Mapping is a per-character Python loop
    — the thing `str.translate` exists here to avoid — so it runs only on text that
    actually carries one, and is bounded exactly as the canary index map is. Past the
    bound the secret is reported spanning the whole text, which drops the value rather
    than redacting part of it: "there is one in here and I cannot say where" is an
    honest answer, and it is the one the canary path gives too.
    """
    hits = _scan_verbatim(stripped)
    if not hits:
        return []
    if len(text) > _MAX_MAPPED_CHARS:
        return [Detection(d.kind, d.confidence, 0, len(text)) for d in hits]
    origin = [i for i, ch in enumerate(text) if ch not in _INVISIBLE]
    return [Detection(d.kind, d.confidence, origin[d.start], origin[d.end - 1] + 1) for d in hits]


def _merge(verbatim: list[Detection], relocated: list[Detection]) -> list[Detection]:
    """Both readings, without reporting one secret twice for the same span."""
    seen = {(d.kind, d.start, d.end) for d in verbatim}
    return verbatim + [d for d in relocated if (d.kind, d.start, d.end) not in seen]


def _scan_verbatim(text: str) -> list[Detection]:
    found: list[Detection] = []

    for m in _DIGIT_RUN.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if luhn_ok(digits) and looks_like_a_pan(digits):
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
