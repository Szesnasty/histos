"""Rendering somebody else's text for a human to read.

Every string a tool source authors — a tool name, a description, an argument name —
is a prompt fragment written by whoever runs the MCP server or published the OpenAPI
document, and the reports in this library are where a human reads it: ``histos
review``, ``histos coverage``, ``histos drift``, ``histos import``. That reader is
about to decide whether to grant the tool, so steering what they see is worth an
attacker's effort, and a terminal will happily be steered — a carriage return rewrites
the line already printed, ``U+202E`` renders ``export_contacts`` as ``stcatnoc_tropxe``
inside an innocent sentence, a zero-width joiner hides a word boundary.

This module exists so there is one answer for every printing path rather than one per
report. It used to live in :mod:`histos.lockfile`, where the drift diff was the only
caller — so the drift report was hardened and every other command printed the same
attacker-authored names raw.
"""

from __future__ import annotations

import re

# The default bound on one rendered value. Enough for a real description, short enough
# that a 200 KB "name" cannot push the rest of the report off the screen.
MAX_DISPLAY_CHARS = 400

# Everything that steers how a line of text *reads* without being visible in it:
# C0/C1 controls, the bidi overrides and isolates (U+202A-U+202E, U+2066-U+2069), the
# zero-width and word-joiner set, and the BOM.
_UNSAFE_TEXT = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f"      # C0 and C1 controls
    "؜​-‏ -‮"   # bidi marks, overrides, line/paragraph separators
    "⁠-⁤⁦-⁯﻿]"  # word joiners, bidi isolates, zero-width no-break space
)


def safe_text(text: str, *, limit: int = MAX_DISPLAY_CHARS) -> str:
    """Render source-authored text so that reading the report cannot be steered by it.

    The text is quoted data and nothing else: never interpolated into a shell, a
    template or a format string, never executed, and never trusted to render as what
    it appears to say. Anything that moves the cursor or reorders the line is escaped
    to its ``\\uXXXX`` spelling, so what a reviewer sees is what a model would receive.
    """
    escaped = _UNSAFE_TEXT.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
    if len(escaped) > limit:
        return escaped[:limit] + f"… (+{len(escaped) - limit} chars)"
    return escaped
