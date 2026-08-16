"""Static regex pattern *data* for the optional content-rules module.

Heuristics, and deliberately **not** used by the core gate — see
:mod:`histos.decide.content_rules` for why. This module only holds the pattern lists;
:class:`~histos.decide.content_rules.ContentRules` decides when (and whether) to
apply them.

The engine has already bounded the complete argument blob before these run. Scanning
only a prefix is not a performance bound — it is an allow path for a forbidden phrase
placed after that prefix.
"""

from __future__ import annotations

import re

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
