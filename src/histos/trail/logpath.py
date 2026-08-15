"""Which file a log is, and whether its bytes still say what they parse to.

Split out of `audit.py`, and the two maps below are the reason this module exists as one
place rather than as a section. `_PATH_LOCKS` is what stops two Gates in one process
interleaving appends into one chain; `_PATH_HIGH_WATER` is what makes a *deleted* log
detectable at all. A second copy of either — the ordinary consequence of a careless
split — breaks both silently, with every test still green.
`tests/test_characterisation.py` pins that they stay single.

Identity is the parent directory\'s `st_dev`/`st_ino` plus the name, folded only when
that volume really folds, measured once per directory. Not the log\'s own inode: that
forgets the file at the exact moment the erasure memory exists to remember it. Not the
platform default either, which guesses — macOS APFS can be formatted case-sensitive, and
on such a volume the guess merged two tenants\' chains.

The two forgery checks are here for the same reason they exist: the chain authenticates
what a line *parses to*, and a line can parse to one thing and read as another.
"""

from __future__ import annotations

import functools
import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any

_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()

# The highest (seq, hash) written to each log by this process. Per path rather
# than per sink: the memory is the whole erasure defence, and a second `JSONLAuditSink`
# on the same file — two Gates in one host, which the lock above exists for — started
# with an empty one and happily wrote a fresh chain over a truncated file. Scoped like
# the lock that protects it.
_PATH_HIGH_WATER: dict[str, tuple[int, str]] = {}


def _duplicate_key(line: str) -> str | None:
    """The first key repeated in one JSON object of ``line``, or None.

    `json.loads` keeps the last value for a repeated key and a human reading the file
    sees the first, which is the one way a line and the record it parses to can say
    different things. `object_pairs_hook` is handed every pair before that collapse
    happens, which is the only place the difference is still visible.
    """
    found: list[str] = []

    def check(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                found.append(key)
            seen.add(key)
        return dict(pairs)

    try:
        json.loads(line, object_pairs_hook=check)
    except ValueError:  # already reported as unparseable by the caller
        return None
    return found[0] if found else None


# A `\u00XX` escape of a printable ASCII character. `json.dumps` never emits one under
# any setting, so a line carrying one was not written by a JSON serialiser.
_ASCII_ESCAPE = re.compile(r"\\u00(?:2[0-9a-fA-F]|[3-6][0-9a-fA-F]|7[0-9a-eA-E])")


def _respelt_ascii(line: str) -> str | None:
    r"""The first `\uXXXX` escape of a printable ASCII character in ``line``, or None.

    The other way a line and the record it parses to can say different things, and the
    one the duplicate-key check misses. `{"effect": "\u0064eny"}` parses to exactly
    `deny` — so the chain authenticates it and every hash matches — while a human
    reading the file, or grepping it for `deny`, finds neither. Nothing legitimate
    produces it: `json.dumps` escapes control characters and, with `ensure_ascii`,
    everything above 0x7E, and never a printable ASCII character.

    The backslash run in front of it has to be counted, because not every occurrence of
    those six characters is an escape. A tool argument holding the *literal text* of one
    — a regex, a code snippet, a fragment of documentation about this very check — is
    serialised by ``json.dumps`` as a doubled backslash followed by five ordinary
    characters. Searching the raw line found that too, so ``verify_chain`` reported a log
    this library had written one line earlier as forged: a verifier crying wolf on an
    honest file, which is worse than no check at all, because it is what teaches an
    operator to stop reading it.

    An escape is real only when the backslashes before it are even in number, each pair
    being one escaped backslash that stands for itself.
    """
    for match in _ASCII_ESCAPE.finditer(line):
        backslashes = 0
        index = match.start()
        while index > 0 and line[index - 1] == "\\":
            backslashes += 1
            index -= 1
        if backslashes % 2 == 0:
            return match.group(0)
    return None


def _path_key(path: Path) -> str:
    """The identity of a log file, for the two module-level maps keyed on it.

    `str(path.resolve())` was the key and it does not canonicalise *case* — and macOS
    APFS and every Windows volume are case-insensitive. So `Trail.jsonl` and
    `trail.jsonl` are one file with two keys: the erasure memory that
    `_PATH_HIGH_WATER` exists to be is defeated by one capital letter, and `_PATH_LOCKS`
    hands two sinks on one file two different locks — on Windows, where `flock` is
    absent, leaving nothing at all serialising them. Both on exactly the two platforms
    this release added to CI.

    Case-folding on darwin and win32 was the first answer, and it guesses. macOS APFS
    can be formatted case-*sensitive* and any mounted image may be, Windows has ReFS and
    WSL mounts, and on such a volume the fold over-merges two genuinely different logs.
    The comment here used to claim the failure direction was the safe one — "a chain
    reported broken rather than an erasure missed" — and that is not what happens. Two
    tenants, `Acme/log.jsonl` and `acme/log.jsonl`, on a case-sensitive volume:
    `acme`'s first-ever record is written with `seq=4` and a `prev` taken from `Acme`'s
    tip, so it is born broken; and one tenant calling the published remedy `rotated()`
    on their own sink clears the *other* tenant's `_PATH_HIGH_WATER` entry, after which
    erasing that other log and appending verifies **clean**. An erasure missed, by the
    documented recovery procedure, from an unprivileged neighbouring log.

    So ask the filesystem instead of the platform — but ask it the right question. The
    identity that matters here is the **location**, not the file: `_PATH_HIGH_WATER`
    exists precisely to remember that a log used to be here after someone deleted it, so
    keying on ``st_ino`` would forget the moment the file did, which is the one moment it
    is for. The location is the parent directory's ``st_dev``/``st_ino`` — which survives
    the log's deletion — plus the name, folded only when that directory's volume really
    does fold, measured once per directory by :func:`_folds_case`.
    """
    resolved = os.path.realpath(path)
    parent = os.path.dirname(resolved) or os.sep
    name = os.path.basename(resolved)
    if _folds_case(parent):
        name = name.casefold()
    try:
        stat = os.stat(parent)
    except OSError:
        # No directory to anchor to. Fold the whole spelling on the same evidence.
        return resolved.casefold() if _folds_case(parent) else resolved
    return f"{stat.st_dev}:{stat.st_ino}:{name}"


@functools.lru_cache(maxsize=512)
def _folds_case(directory: str) -> bool:
    """Whether this directory's volume treats two spellings of a name as one file.

    Measured, read-only, once per directory per process: stat the directory under its
    own name and under a case-swapped spelling of that name, and ask whether both
    landed on the same inode. If a *different* directory happens to occupy the swapped
    spelling the answer is still right — two spellings coexisting as distinct entries is
    what case-sensitive means.

    Falls back to the platform default only when there is nothing to measure: a name
    with no cased characters at all, or a filesystem error. Under that fallback this
    behaves exactly as the old unconditional fold did.
    """
    parent, name = os.path.split(directory)
    swapped = name.swapcase()
    if parent and swapped != name:
        try:
            return os.path.samestat(os.stat(directory), os.stat(os.path.join(parent, swapped)))
        except OSError:
            return False
    return sys.platform in ("darwin", "win32")


def tip_path_for(log: str | Path) -> Path:
    """The sidecar that binds a hash-chained log to its length. See :class:`JSONLAuditSink`."""
    p = Path(log)
    return p.with_name(p.name + ".tip")
