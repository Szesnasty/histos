"""Static regex pattern *data* for the optional content-rules module.

Heuristics, and deliberately **not** used by the core gate — see
:mod:`histos.content_rules` for why. This module only holds the pattern lists
and the scan bound; :class:`~histos.content_rules.ContentRules`
decides when (and whether) to apply them.

Every match is length-bounded to avoid ReDoS: an argument blob longer than
``_MAX_SCAN_LEN`` is truncated before matching, so a pathological input cannot
stall the caller.
"""

from __future__ import annotations

import re

_MAX_SCAN_LEN = 8_000

# Injected instructions attempting to override the agent's own rules.
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"you\s+are\s+now\b",
        r"new\s+system\s+prompt",
        r"reveal\s+(your\s+)?(system\s+)?prompt",
        r"disregard\s+(all\s+)?(prior|previous|above)",
        r"override\s+(all\s+)?rules",
        r"act\s+as\s+(an?\s+)?unrestricted",
        r"do\s+anything\s+now",
        r"jailbreak",
        r"<\|im_start\|>",
        r"\[INST\]",
        r"<<SYS>>",
        r"###\s*(system|assistant)\s*:",
    ]
]

# Arguments that look like bulk data-exfiltration or destructive SQL.
EXFILTRATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(list|show|get|dump|export)\s+(all|every)\s+(user|customer|record|data|secret|key|password)",
        r"(enumerate|extract|download)\s+.*\b(database|table|record)",
        r"bulk\s+(export|download|extract)",
        r"select\s+\*\s+from",
        r"(drop|delete|truncate|alter)\s+(table|database)",
    ]
]
