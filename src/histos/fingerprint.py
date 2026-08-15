"""The structural view a policy hash is taken over.

Split out of `contracts.py`. `content_hash` is a contract rather than an implementation
detail: approvals bind to it, policy pinning rests on it, every audit record names it,
and the spec requires a second implementation to reproduce it byte for byte. Two
properties follow, and both were once false.

It must be **injective** — two policies that decide differently must not share a hash. A
keyword that enforces something and is missing from the structure below produces exactly
that collision, which is what happened to `unique_items`: one hash, opposite verdicts,
and `histos drift` reporting CLEAN across the flip.

It must be **deterministic** — the same policy hashes the same in every process. A
set-valued field rendered in iteration order captured `PYTHONHASHSEED`, which silently
unbinds an approval issued by one worker from every other worker.
"""

from __future__ import annotations

from typing import Any

from histos.canonical import normalize_numbers
from histos.schema import Schema


def _schema_structure(schema: Schema | None) -> Any:
    """Every declared keyword of a schema, typed exactly as it was written.

    *Every* one. A keyword that enforces something and is not listed here is a pair of
    policies that decide differently and hash the same — so an approval issued against
    one binds the other, `histos drift` reports CLEAN across the flip, and the lock's
    `contract_sha256` collides. `unique_items` was left out when it was added and did
    all four. `tests/test_release_round4.py` now walks `Field`'s dataclass fields and
    fails on the next omission rather than waiting for a review to find it.
    """
    if schema is None:
        return None
    return {
        "allow_extra": schema.allow_extra,
        "fields": {
            name: {
                "type": f.type,
                "required": f.required,
                "enum": list(f.enum) if f.enum is not None else None,
                "max_length": f.max_length,
                "min_length": f.min_length,
                "pattern": f.pattern,
                "sensitive": f.sensitive,
                "nullable": f.nullable,
                "item_enum": list(f.item_enum) if f.item_enum is not None else None,
                "item_type": f.item_type,
                "max_items": f.max_items,
                "min_items": f.min_items,
                "unique_items": f.unique_items,
                "minimum": f.minimum,
                "maximum": f.maximum,
                "exclusive_minimum": f.exclusive_minimum,
                "exclusive_maximum": f.exclusive_maximum,
                "multiple_of": f.multiple_of,
            }
            for name, f in schema.fields.items()
        },
    }


def _schema_fingerprint(schema: Schema | None) -> Any:
    """The **lock's** view of a schema, with every bound flattened to decimal text.

    This exact structure is pinned by ``conformance/projection`` and is what
    ``contract_sha256`` is defined over, so it is a published artifact and does not
    move. It shares one rule with ``content_hash`` — every number is rendered through
    :func:`histos.canonical.canonical_number`, so `500` and `500.0` are one policy —
    but not one *encoding*: flattening a number to a bare string is lossy, and
    `Policy.content_hash` needs a form in which the integer `1` and the string `"1"`
    stay distinguishable (see :meth:`Policy.fingerprint`).
    """
    return normalize_numbers(_schema_structure(schema))


# A canary is a token planted to be conspicuous; anything this short is a fragment of
# one, and matching it turns every ordinary argument into an exfiltration alert. Lives
# here rather than in `bundle`, so the Python constructor and the file format cannot
# come to different conclusions about the same policy.
