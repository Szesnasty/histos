"""One canonical serializer for arguments (Phase 0.1).

The audit digest, the approval fingerprint, and (later) idempotency all need to
answer "is this the *same* action?" deterministically. The old `json.dumps(...,
default=str)` collides `1` with `"1"`, is unstable for sets, and silently
stringifies objects — so two different actions could share a fingerprint, or one
action could fingerprint differently across processes.

`canonical_json` produces a stable, **type-tagged** string: every scalar carries a
type tag (`["i", 1]` vs `["s", "1"]`), containers are ordered deterministically,
and a value that cannot be represented (a function, an arbitrary object) raises
rather than being silently coerced. Non-finite floats are rejected (they cannot
compare consistently). This is the single serializer the fingerprint-dependent
primitives share.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

# A lone (unpaired) surrogate survives `json.loads` — `{"q": "\ud800"}` is how every
# framework parses an LLM tool call — but has no UTF-8 encoding, so it detonates at
# `.encode()` rather than here. Catching it in the serializer is what lets the two
# callers fail the way each of them should: the approval fingerprint refuses to
# fingerprint an action it cannot represent (fail-closed), and the audit digest
# falls back to a stable form instead of taking the whole record down with it.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


# How deep a value may nest before this refuses to canonicalise it. CPython's own limit
# is around a thousand frames and each level here costs two, so a walk that keeps going
# raises `RecursionError` from wherever it happens to be — and this one runs on the
# *argument* digest, before any decision has been reached. A self-referential argument
# therefore reached the caller as an unhandled `RecursionError` with nothing written to
# the trail: no execution, which is the right direction, but no decision and no record
# either, which is not a denial, it is an absence. The bound is far past any real
# document and short of the interpreter's.
_MAX_CANON_DEPTH = 200


def _canon(obj: Any, numbers_as_text: bool, _open: tuple[int, ...] = ()) -> Any:
    # bool BEFORE int (bool is a subclass of int) so True never tags as ["i", 1].
    if isinstance(obj, bool):
        return ["b", obj]
    if obj is None:
        return ["n", None]
    if isinstance(obj, (int, float)):
        if isinstance(obj, float) and not math.isfinite(obj):
            raise ValueError(f"non-finite float is not canonicalizable: {obj!r}")
        if numbers_as_text:
            # One tag for both, because the *source document* could not tell them
            # apart: `JSON.parse` collapses 1 and 1.0 to one number. Keeping the tag
            # distinct from ["s", …] is the whole point — it is what stops the
            # integer 1 and the string "1" from sharing a policy hash while reaching
            # opposite verdicts. See `canonical_number`.
            return ["f", canonical_number(obj)]
        if isinstance(obj, int):
            return ["i", obj]
        # repr gives a stable, round-trippable text form; normalize -0.0 to 0.0.
        return ["f", repr(obj + 0.0)]
    if isinstance(obj, str):
        if _LONE_SURROGATE.search(obj):
            raise ValueError("string contains an unpaired surrogate and has no UTF-8 encoding")
        return ["s", obj]
    if isinstance(obj, bytes):
        return ["y", obj.hex()]
    if isinstance(obj, (list, tuple, set, frozenset, dict)):
        # Only the containers currently *open* on this path, so a value referenced twice
        # from one structure — a shared child, which is ordinary — still canonicalises,
        # and only a genuine cycle is refused. Ids are safe to compare here because every
        # container in `_open` is reachable from the argument being walked and so cannot
        # be freed and its address handed to something else mid-walk.
        inner = _open + (id(obj),)
        if id(obj) in _open:
            raise ValueError("value contains a reference cycle, so it has no canonical form")
        if len(inner) > _MAX_CANON_DEPTH:
            raise ValueError(f"value nests deeper than {_MAX_CANON_DEPTH}, past what can be canonicalised")
    else:
        inner = _open

    if isinstance(obj, (list, tuple)):
        return ["l", [_canon(x, numbers_as_text, inner) for x in obj]]
    if isinstance(obj, (set, frozenset)):
        items = sorted(
            (_canon(x, numbers_as_text, inner) for x in obj),
            key=lambda c: json.dumps(c, sort_keys=True, ensure_ascii=False),
        )
        return ["t", items]
    if isinstance(obj, dict):
        pairs = sorted(
            ([_canon(k, numbers_as_text, inner), _canon(v, numbers_as_text, inner)] for k, v in obj.items()),
            key=lambda p: json.dumps(p[0], sort_keys=True, ensure_ascii=False),
        )
        return ["d", pairs]
    raise ValueError(f"value of type {type(obj).__name__!r} is not canonicalizable")


def canonical_json(obj: Any, *, numbers_as_text: bool = False) -> str:
    """Deterministic, type-tagged JSON string. Raises ValueError on un-representable input.

    ``numbers_as_text=True`` is the *published-hash* mode: every number is rendered
    through :func:`canonical_number` and tagged ``["f", …]`` whether it arrived as an
    int or a float, so a hash a second implementation must reproduce does not depend
    on a distinction that implementation's JSON parser cannot see. Types are still
    tagged, so this is strictly weaker than the default mode in exactly one place and
    nowhere else.
    """
    return json.dumps(_canon(obj, numbers_as_text), separators=(",", ":"), ensure_ascii=False)


def canonical_fingerprint(obj: Any) -> str:
    """A hex SHA-256 over the canonical form — the stable identity of an action."""
    import hashlib

    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def canonical_number(value: int | float) -> str:
    """A decimal string that two languages agree on for the same numeric value.

    The type tagging above is what makes canonical forms unambiguous *within* a
    language, and what makes them ambiguous *between* two. Python's ``json.loads``
    keeps the distinction the document wrote — ``1`` is an int, ``1.0`` a float — so
    they serialise as ``["i",1]`` and ``["f","1.0"]`` and hash differently.
    **JavaScript cannot see that distinction at all**: ``JSON.parse`` collapses both
    to one number. Any hash computed over raw numbers is therefore reproducible in
    Python and not reproducible anywhere else, which is the same as not being
    reproducible.

    So every number entering a published hash is rendered as text first, and the tag
    stops carrying information the source never had. Integral values lose the
    fractional part; the rest use the shortest round-trip form, which Python's
    ``repr`` and JavaScript's ``String`` agree on for ordinary magnitudes.

    **Named limit:** values whose shortest round-trip form uses exponent notation are
    not guaranteed identical across languages (``1e-07`` here, ``1e-7`` there). Policy
    bounds are amounts, lengths and counts, so this is a corner — but it is a corner,
    and it is written down rather than discovered.
    """
    # Integers never go through float. They used to, and that lost the two properties
    # this function exists to provide: `2**53` and `2**53+1` rendered identically, so
    # two genuinely different policies shared one `content_hash` and a pinned hash
    # accepted the wrong ruleset; and an int beyond ~1.8e308 raised OverflowError, so
    # a bound the engine can enforce exactly made hashing the policy — and therefore
    # constructing a Gate — crash. `str(int)` is also what JavaScript's `String`
    # produces for every integer it can hold, so the cross-language agreement above
    # is preserved rather than traded away.
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    number = float(value)
    return str(int(number)) if number.is_integer() else repr(number)


def normalize_numbers(node: Any) -> Any:
    """Recursively render every number in a structure via :func:`canonical_number`.

    Applied to a fingerprint before it is hashed, never to values the engine compares
    or enforces — a bound is still a number where it does arithmetic.
    """
    if isinstance(node, bool):  # before int — bool is a subclass of it
        return node
    if isinstance(node, int | float):
        return canonical_number(node)
    if isinstance(node, dict):
        return {k: normalize_numbers(v) for k, v in node.items()}
    if isinstance(node, list | tuple):
        return [normalize_numbers(v) for v in node]
    return node
