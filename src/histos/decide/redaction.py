"""Taking things out of a value without changing what it is.

Split out of `engine.py`. Four passes share one problem: they walk an arbitrary
structure, remove something from it, and have to hand back the same *shape* — a
NamedTuple that comes back a plain tuple, or a dict whose key collided with a redacted
twin, is a bug in the caller\'s code rather than in the policy. `_rebuild_container`
exists for exactly that, and every pass here goes through it.

The passes: canary tokens (both tiers), recognised secrets, declared-sensitive fields,
and `project_output`, which is deny-by-default on the return surface.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any

from histos.decide import canary, detectors
from histos.policy.schema import validate


def _with_ordinal(key: Any, n: int) -> Any:
    return key + f"#{n}".encode() if isinstance(key, bytes) else f"{key}#{n}"


def _put_redacted_key(out: dict[Any, Any], key: Any, value: Any) -> None:
    """Insert a key that redaction may have rewritten, without dropping a record.

    Two distinct secrets used as dict keys both redact to the same mark, so a plain
    assignment collapses two records into one — silent data loss in the middle of a
    security control, and invisible in the audit trail. Colliding redacted keys get an
    ordinal suffix instead. Every key goes through here, including untouched ones: a
    redacted key can also collide with a *literal* key that already spells the mark,
    and it was the untouched one that overwrote the record.
    """
    if key in out:
        n = 2
        while _with_ordinal(key, n) in out:
            n += 1
        key = _with_ordinal(key, n)
    out[key] = value


def _rebuild_container(obj: Any, items: list[Any]) -> Any:
    """Rebuild a sequence/set container of the same type from redacted ``items``.

    ``type(obj)(items)`` is wrong for a NamedTuple — its constructor takes positional
    fields, so redacting a NamedTuple return raised TypeError, which the post-gate
    turned into a fail-closed DENY *after* the tool had already run: the side effect
    happened and the caller got a denial. A tuple subclass that cannot be rebuilt at all
    degrades to a plain tuple; losing the type is acceptable, losing the redaction (or
    the call) is not.
    """
    make = getattr(obj, "_make", None)  # NamedTuple
    if isinstance(obj, tuple) and callable(make):
        try:
            return make(items)
        except (TypeError, ValueError):
            return tuple(items)
    try:
        return type(obj)(items)
    except (TypeError, ValueError):
        if isinstance(obj, list):
            return list(items)
        if isinstance(obj, frozenset):
            return frozenset(items)
        if isinstance(obj, set):
            return set(items)
        return tuple(items)


def _redact_structure(obj: Any, tokens: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively replace canary tokens in strings within ``obj``.

    Traverses str, bytes, dict (keys *and* values), list, tuple, set and
    frozenset, matching verbatim *and* normalized — the same two tiers the pre-gate
    applies, so the output channel is not the cheap way around the control.
    **Residual (honest):** it cannot reach into opaque objects (dataclass/Pydantic
    attributes, custom __str__), so a canary hidden inside such an object's fields is
    not redacted — canary is a mechanical, structural control, not a general
    exfiltration guard (see SECURITY.md).
    """
    found: list[str] = []
    if isinstance(obj, str):
        out_s, found = canary.redact(obj, tokens)
        out_s, norm_hits = canary.redact_normalized(out_s, tokens)
        found.extend(tok for tok in norm_hits if tok not in found)
        return out_s, found
    if isinstance(obj, bytes):
        out_b = obj
        for tok in sorted(tokens, key=len, reverse=True):  # longer first (see canary.redact)
            tb = tok.encode("utf-8", "ignore")
            if tb and tb in out_b:
                found.append(tok)
                out_b = out_b.replace(tb, b"[REDACTED-CANARY]")
        # surrogateescape round-trips any byte string exactly, so normalized matching
        # can run on text without disturbing a single byte outside a hit.
        text, norm_hits = canary.redact_normalized(out_b.decode("utf-8", "surrogateescape"), tokens)
        if norm_hits:
            found.extend(tok for tok in norm_hits if tok not in found)
            out_b = text.encode("utf-8", "surrogateescape")
        return out_b, found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k, khits = _redact_structure(k, tokens)
            new_v, vhits = _redact_structure(v, tokens)
            _put_redacted_key(out, new_k, new_v)
            found.extend(khits)
            found.extend(vhits)
        return out, found
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = []
        for v in obj:
            new_v, hits = _redact_structure(v, tokens)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found


def _validate_output(schema: Any, out: Any) -> list[str]:
    """Validate a tool output against its declared return schema.

    A dict is validated directly; a list/tuple is validated element-by-element
    (each must be an object); anything else is an unknown structure and fails.
    """
    if isinstance(out, dict):
        return validate(schema, out)
    if isinstance(out, (list, tuple)):
        errors: list[str] = []
        for i, item in enumerate(out):
            if isinstance(item, dict):
                errors.extend(f"[{i}] {e}" for e in validate(schema, item))
            else:
                errors.append(f"[{i}] is not an object")
        return errors
    return ["output is not an object or list of objects"]


def _redact_sensitive(obj: Any, sensitive_names: frozenset[str]) -> tuple[Any, list[str]]:
    """Recursively redact any dict key in ``sensitive_names`` — anywhere in ``obj``.

    Applies to nested structures and to *lists of records* (a common tool return),
    which the earlier top-level-dict-only check silently leaked. Redaction is by
    field *name* anywhere in the structure (conservative: over-redacts a same-named
    field rather than leak a sensitive one).
    """
    found: list[str] = []
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if k in sensitive_names:
                out[k] = "[REDACTED]"
                found.append(str(k))
            else:
                out[k], hits = _redact_sensitive(v, sensitive_names)
                found.extend(hits)
        return out, found
    if isinstance(obj, (list, tuple)):
        items = []
        for v in obj:
            new_v, hits = _redact_sensitive(v, sensitive_names)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found


# What the projector can look inside. Anything else is a leaf it walks past without
# being able to say whether it carried an undeclared field.
_PROJECTABLE = (dict, list, tuple, set, frozenset)
_INSPECTABLE_LEAF = (str, bytes, bytearray, int, float, bool, type(None))
# The exact builtins, which cannot carry an attribute. Only a subclass can, and telling
# the two apart by `type()` is what keeps `_leaf_fields` off the hot path.
_EXACT_LEAF = frozenset(_INSPECTABLE_LEAF)


def _record_fields(value: Any) -> dict[str, Any] | None:
    """The author-defined ``name -> value`` bindings this object publishes, or None.

    `project_output` drops undeclared *fields*, and a field is a name a tool author
    chose. Three shapes publish those names well enough to read them — a dataclass
    instance, a NamedTuple, and anything keeping its state in an instance `__dict__`
    (which covers Pydantic v1 and v2 models and every ordinary class). Reading them is
    strictly better than the two things this code did before: naming the type in the
    trail and letting the undeclared field egress anyway, or refusing the whole return.

    An `Enum` member is excluded even though it carries a `__dict__` (`_name_`,
    `_value_`, `_sort_order_`): those are the enum machinery's, not the author's, and a
    member's value *is* its identity. It belongs with `int`, not with a record.

    The residual is an object whose state lives only in `__slots__` — a user class that
    declares them, and the stdlib value types that do (`UUID`, `IPv4Address`). Slots
    cannot separate the two: reading them would project a `UUID` into
    `{"int": ..., "is_safe": ...}` and destroy the value. So slots-only objects stay
    leaves, are named in the trail, and are covered by `strict_returns` instead —
    written down in SECURITY.md rather than half-handled here.
    """
    if isinstance(value, (type, enum.Enum)):
        return None
    # A leaf is a leaf even when it carries attributes. `class Money(str)` with a
    # `currency` on it has a non-empty `__dict__`, so the check below read it as a
    # record and shredded `Money("12.30")` into `{"currency": "EUR"}` — the value the
    # caller asked for, replaced by its decoration. Anything the scanners can already
    # read end to end is a value; only the fields hanging off it would be undeclared,
    # and dropping the value to reach them is not a trade worth making.
    if isinstance(value, _INSPECTABLE_LEAF):
        return None
    if dataclasses.is_dataclass(value):
        return {f.name: getattr(value, f.name) for f in dataclasses.fields(value) if hasattr(value, f.name)}
    names = getattr(value, "_fields", None)
    if isinstance(value, tuple) and isinstance(names, tuple) and all(isinstance(n, str) for n in names):
        return {n: getattr(value, n) for n in names if hasattr(value, n)}
    state = getattr(value, "__dict__", None)
    if isinstance(state, dict) and state:
        return {k: v for k, v in state.items() if isinstance(k, str)}
    return None


def _leaf_fields(value: Any) -> dict[str, Any] | None:
    """What hangs *off* a leaf — the half `_record_fields` refuses, for the scanners.

    The refusal above is right for the projector and wrong for everything downstream of
    it. Projection must not shred `Money("12.30")` into `{"currency": "EUR"}`; the canary
    scan and the secret detectors have the opposite job, which is to read every string
    reachable from the output. A token on such an attribute was reachable by the caller
    and invisible to both — `class Money(str)` with the canary on it left through the
    *default* configuration with `effect=allow` and `redactions: []`, so the trail called
    the output clean. The sixth distinct shape a canary has escaped in, and the first
    where a scan and a projection wanting different answers was the reason.

    An exact builtin is the overwhelmingly common case and has no instance dictionary at
    all, so it costs one `type()` lookup. Only a *subclass* can carry anything here.
    """
    if type(value) in _EXACT_LEAF or not isinstance(value, _INSPECTABLE_LEAF):
        return None
    state = getattr(value, "__dict__", None)
    found = {k: v for k, v in state.items() if isinstance(k, str)} if isinstance(state, dict) else {}
    # Slots too. A leaf subclass that declares them keeps its attributes off `__dict__`,
    # and the point here is reachability, not how the class chose to store it. `UUID` and
    # friends are not leaves, so the reason slots stay opaque in `_record_fields` — that
    # reading them would project a value into its internals — does not apply.
    #
    # Every class in the MRO, and `__slots__` may be one bare string. Reading it off the
    # instance's own class alone missed `class Money(str): __slots__ = ("currency",)`
    # subclassed once more, which is ordinary, and this comment claimed slots were
    # covered while a token in an inherited one was still unreachable.
    for klass in type(value).__mro__:
        declared = getattr(klass, "__slots__", ())
        for name in (declared,) if isinstance(declared, str) else declared or ():
            if isinstance(name, str) and name not in found and hasattr(value, name):
                found[name] = getattr(value, name)
    return found or None


def _projectable(value: Any) -> bool:
    """Whether the projector can act on this shape at all.

    `isinstance(out, tuple)` was the test and a `NamedTuple` passes it — so the
    projector rebuilt the container, returned each non-dict element untouched, dropped
    nothing, and reported the clean result the guard was written to prevent. A tuple
    subclass carries its fields by *name*, so a tuple is asked by exact type and the
    named shapes go through `_record_fields`, which can read those names.

    Only a tuple. Answering *every* container by exact type was the overcorrection, and
    it refused the shapes a real tool returns most often: `Counter`, `OrderedDict`,
    `defaultdict` and any `list` subclass, all of which the projector enters and
    rebuilds correctly, because a dict subclass still carries its data under keys and a
    list subclass still carries it positionally. Neither hides a field behind a name.
    """
    return isinstance(value, (dict, list, set, frozenset)) or type(value) is tuple or _record_fields(value) is not None


def _project_output(obj: Any, allowed: frozenset[str]) -> tuple[Any, list[str], list[str]]:
    """Deny-by-default on the OUTPUT surface: drop any dict key not in ``allowed``.

    The surgical alternative to strict_returns' all-or-nothing — an undeclared field
    (where a secret can hide, out of reach of name-based redaction) simply never
    egresses. Recurses into nested objects and lists-of-records.
    """
    dropped: list[str] = []
    opaque: list[str] = []
    # Keyed on `id`, and the value keeps the original alive so the id cannot be recycled
    # under us. Without it a record whose two fields point at one child re-walks that
    # child twice, which is 2**depth for a shared graph — 22 tiny objects were enough to
    # stop the post-gate returning — and a record that reaches itself never terminates.
    memo: dict[int, Any] = {}

    def go(o: Any) -> Any:
        if isinstance(o, dict):
            kept: dict[Any, Any] = {}
            for k, v in o.items():
                if k in allowed:
                    kept[k] = go(v)
                else:
                    dropped.append(str(k))
            return kept
        # Exactly the shapes `_projectable` vouches for, and asked the same way. A
        # `NamedTuple` is a tuple subclass and passed `isinstance(o, tuple)`, so one
        # level down — a list of record rows, the single most ordinary return there is —
        # it was rebuilt field for field with every undeclared field intact, and because
        # this branch won before the leaf check it was not even added to `opaque`. The
        # audit record read `redactions: []`: byte-identical to "there was nothing
        # undeclared to drop". The top-level guard refused that exact value.
        if isinstance(o, (list, set, frozenset)) or type(o) is tuple:
            return _rebuild_container(o, [go(x) for x in o])
        # An object that publishes its field names: read them and drop the undeclared
        # ones, which is what the knob promises and what neither previous behaviour did.
        # The result is a plain mapping, because a record minus a required field cannot
        # be rebuilt as itself — but only when something actually had to go, so a
        # correctly declared return keeps its type and a caller's `.field` access with
        # it. That is the same bargain a dict gets: unchanged unless there was something
        # to remove.
        fields = _record_fields(o)
        if fields is not None:
            if id(o) in memo:
                return memo[id(o)][1]
            memo[id(o)] = (o, o)  # in progress: a cycle resolves to the object itself
            kept_fields: dict[str, Any] = {}
            changed = False
            for name, value in fields.items():
                if name not in allowed:
                    dropped.append(name)
                    changed = True
                    continue
                projected = go(value)
                changed = changed or projected is not value
                kept_fields[name] = projected
            # Always a mapping, never the original object. Returning the record
            # unchanged when nothing had to be dropped read as a courtesy — the caller
            # keeps its type — and was a hole: the passes that run *after* projection
            # walk mappings and sequences, so a record handed back intact sailed past
            # the canary scan and the secret detectors with `redactions: []`. A planted
            # token inside a fully declared field egressed, and the audit line said the
            # output was clean. Projection is opt-in and it is a transforming control;
            # a caller who switched it on is asking for a filtered mapping, and one
            # every later pass can read is the only kind worth handing back.
            memo[id(o)] = (o, kept_fields)
            return kept_fields
        # A value the projector cannot enter — a slots-only object, or a C type keeping
        # its state where no Python attribute shows it. It is returned as it came, and
        # it is *named*, so the audit record can tell "there was nothing undeclared to
        # drop" from "there was something here nobody could look inside".
        if not isinstance(o, _INSPECTABLE_LEAF):
            opaque.append(type(o).__name__)
        return o

    return go(obj), dropped, opaque


def _redact_secrets_structure(obj: Any) -> tuple[Any, list[str]]:
    """Redact recognised secrets (checksum + structural) in every string leaf.

    Traverses exactly what the canary traverser does — str, bytes, dict keys *and*
    values, list, tuple, set, frozenset. It used to skip dict keys and bytes entirely,
    so a key→credential map (an AWS key listing) or any tool returning bytes (an HTTP
    body, a file read) handed the model the credential in the clear, with nothing in
    the audit trail: a leak the operator could not even see.
    """
    found: list[str] = []
    if isinstance(obj, str):
        red, kinds = detectors.redact_string(obj)
        found.extend(kinds)
        return red, found
    if isinstance(obj, bytes):
        # surrogateescape round-trips every byte, so only the detected span changes.
        red, kinds = detectors.redact_string(obj.decode("utf-8", "surrogateescape"))
        if not kinds:
            return obj, found
        found.extend(kinds)
        return red.encode("utf-8", "surrogateescape"), found
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            new_k, khits = _redact_secrets_structure(k)
            new_v, vhits = _redact_secrets_structure(v)
            _put_redacted_key(out, new_k, new_v)
            found.extend(khits)
            found.extend(vhits)
        return out, found
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = []
        for v in obj:
            new_v, hits = _redact_secrets_structure(v)
            items.append(new_v)
            found.extend(hits)
        return _rebuild_container(obj, items), found
    return obj, found
