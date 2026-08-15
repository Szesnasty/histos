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

    So ask the filesystem instead of the platform — but ask it the right question, and
    note that the two maps do not ask the same one. This key is the **erasure memory's**,
    and it has to survive `rm -rf logs && mkdir logs`: a recreated directory is a new
    inode, so anchoring to one orphaned the high-water mark exactly when a deployment
    wiped a volume, and the replaced log verified clean. The resolved spelling survives
    that, folded only when the volume really does fold, measured once per directory by
    :func:`_folds_case`.

    The lock wants the opposite and has :func:`_lock_key` for it.
    """
    resolved = os.path.realpath(path)
    parent = os.path.dirname(resolved) or os.sep
    return resolved.casefold() if _folds_case(parent) else resolved


def _lock_key(path: Path) -> str:
    """Which *file* this is, for the write lock — the other question, and its opposite.

    `_path_key` must be stable when a path is recreated. A lock must do the reverse:
    collapse every spelling of one file onto one entry. `realpath` resolves symlinks and
    nothing else, and a macOS firmlink (`/System/Volumes/Data/Users/…`) and a Linux bind
    mount each give one file a second spelling it cannot see through. Two sinks reaching
    one log that way took two different locks and interleaved appends into one hash
    chain, which is the one thing the trail cannot survive — and on Windows, where
    `flock` is absent, with nothing else serialising them.

    One key answering both questions could only ever satisfy one of them. The parent
    directory's ``(st_dev, st_ino)`` answers identically through either spelling, and
    anchoring the *lock* to it costs nothing when a directory is recreated: a sink
    holding the old lock has a descriptor on the deleted inode and is not writing to the
    new file at all.
    """
    resolved = os.path.realpath(path)
    parent = os.path.dirname(resolved) or os.sep
    name = os.path.basename(resolved)
    if _folds_case(parent):
        name = name.casefold()
    try:
        stat = os.stat(parent)
    except OSError:
        # Nothing to anchor to — a log under a directory that does not exist yet. The
        # spelling is all there is, which is what the other key uses.
        return _path_key(path)
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
    # Probe an entry *inside* the directory, not the directory's own name. The name
    # lives on the parent's volume, and at a mount point those are different
    # filesystems — a case-sensitive image mounted under a case-insensitive one answered
    # for the wrong one, which is the configuration a per-tenant volume produces.
    try:
        children = os.listdir(directory)
    except OSError:
        children = []
    for child in children[:64]:
        swapped = child.swapcase()
        if swapped == child:
            continue
        try:
            return os.path.samestat(os.stat(os.path.join(directory, child)), os.stat(os.path.join(directory, swapped)))
        except OSError:
            # This one spelling does not resolve. `str.swapcase` is not the volume's
            # folding table — U+0131 DOTLESS I, ordinary in Turkish, swapcases to ASCII
            # `I`, which APFS does not fold back — so a miss says nothing about the
            # volume and the next child is tried.
            continue
    parent, name = os.path.split(directory)
    swapped = name.swapcase()
    if parent and swapped != name:
        try:
            return os.path.samestat(os.stat(directory), os.stat(os.path.join(parent, swapped)))
        except OSError:
            pass
    # Nothing measurable. The platform default, which is what the docstring promises and
    # what this library did before the probe existed.
    return sys.platform in ("darwin", "win32")


def tip_path_for(log: str | Path) -> Path:
    """The sidecar that binds a hash-chained log to its length. See :class:`JSONLAuditSink`."""
    p = Path(log)
    return p.with_name(p.name + ".tip")
