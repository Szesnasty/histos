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
from typing import Any


def _canon(obj: Any) -> Any:
    # bool BEFORE int (bool is a subclass of int) so True never tags as ["i", 1].
    if isinstance(obj, bool):
        return ["b", obj]
    if obj is None:
        return ["n", None]
    if isinstance(obj, int):
        return ["i", obj]
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError(f"non-finite float is not canonicalizable: {obj!r}")
        # repr gives a stable, round-trippable text form; normalize -0.0 to 0.0.
        return ["f", repr(obj + 0.0)]
    if isinstance(obj, str):
        return ["s", obj]
    if isinstance(obj, bytes):
        return ["y", obj.hex()]
    if isinstance(obj, (list, tuple)):
        return ["l", [_canon(x) for x in obj]]
    if isinstance(obj, (set, frozenset)):
        items = sorted((_canon(x) for x in obj), key=lambda c: json.dumps(c, sort_keys=True, ensure_ascii=False))
        return ["t", items]
    if isinstance(obj, dict):
        pairs = sorted(
            ([_canon(k), _canon(v)] for k, v in obj.items()),
            key=lambda p: json.dumps(p[0], sort_keys=True, ensure_ascii=False),
        )
        return ["d", pairs]
    raise ValueError(f"value of type {type(obj).__name__!r} is not canonicalizable")


def canonical_json(obj: Any) -> str:
    """Deterministic, type-tagged JSON string. Raises ValueError on un-representable input."""
    return json.dumps(_canon(obj), separators=(",", ":"), ensure_ascii=False)


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
