"""Containers that refuse to be edited, and the snapshot that builds them.

Split out of `contracts.py`. Two objects in this library must not change after something
has been decided against them: a Gate\'s ruleset, because every audit record names the
hash computed before the edit, and a bound `Principal`, because the next call is
authorized against it. Both were frozen dataclasses whose *contents* were ordinary
mutable dicts and lists, which is not the same thing at all — and the gap was found
three times at three different depths.

`ReadOnlyDict` and `ReadOnlyList` are subclasses rather than proxies or tuples, and both
choices are load-bearing. A `MappingProxyType` is not a `dict` to `dataclasses.asdict`
or to `pickle`; a `tuple` is not a `list` to a `Constraint` comparing `== ["acme"]`, so
substituting one would silently flip authorization verdicts.

`_snapshot_value` asks `deepcopy` first and falls back to walking the structure only
when something inside declines to be copied — a lock, a session, an open file. The walk
alone lost cycles, `defaultdict` factories and namedtuple types; `deepcopy` alone failed
the whole subtree when one leaf refused.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


class ReadOnlyDict(dict):  # type: ignore[type-arg]
    """A mapping that refuses to be edited, and is still a `dict` to the stdlib.

    `MappingProxyType` was the obvious choice and cost two things the stdlib does by
    `isinstance(obj, dict)`. `dataclasses.asdict` recurses into exact dicts, lists and
    dataclasses and falls back to `copy.deepcopy` for everything else — and a proxy
    cannot be deep-copied, so `dataclasses.asdict(gate.policy)` raised. `pickle` has the
    same hole, which `Policy.__getstate__` had to paper over. A `dict` subclass takes
    those branches, and refusing every mutator keeps the guarantee the proxy was chosen
    for: a ruleset a Gate owns cannot be edited under a `policy_hash` computed before
    the edit.
    """

    __slots__ = ()

    def _readonly(self, *_a: Any, **_k: Any) -> Any:
        raise TypeError(
            "this mapping is read-only: a Gate's ruleset cannot be edited in place, because every audit "
            "record would keep naming the hash computed before the edit. Swap the whole policy with "
            "`gate.policy = ...`, which re-hashes."
        )

    def __setitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __delitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def pop(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def popitem(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def clear(self) -> None:
        self._readonly()

    def update(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def setdefault(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __ior__(self, _other: Any) -> Any:  # type: ignore[misc]
        # `d |= {...}` calls `__ior__`, which for a dict mutates IN PLACE and then
        # returns self for the assignment. On a frozen dataclass field the assignment
        # fails with `FrozenInstanceError` — and the mutation has already landed. So
        # `gate.policy.permissions |= {"evil": {...}}` raised, looked refused, and left
        # the grant live on the Gate under the `policy_hash` computed before it:
        # measured, a role with no grant executing a write tool with the trail naming
        # the same ruleset for the denial and the allow.
        #
        # This override was here and was removed to silence mypy's "signatures of
        # __ior__ and __or__ are incompatible" — a variance complaint about a method
        # that exists to raise. The `type: ignore` is the right answer; deleting the
        # guard was not.
        self._readonly()

    def __reduce__(self) -> Any:
        return (self.__class__, (dict(self),))

    def copy(self) -> dict[str, Any]:
        return dict(self)


def _snapshot(attributes: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy what can be copied; keep what cannot, rather than refusing the request.

    The copy exists so a tool handed a bound attribute cannot edit the trust anchor
    through it. But a host legitimately parks unclonable things here — a database
    session, an HTTP client, a lock — and `deepcopy` raises on those, which turned
    building a `Principal` into something that could fail. A host builds one per
    request, so that is an outage, and it is a worse outcome than the sharing it
    prevents: an object with no `__deepcopy__` is one a tool could not meaningfully
    mutate into a different authorization answer anyway. Copy per value, so one
    uncopyable entry does not cost the snapshot on the others.
    """
    return {key: _snapshot_value(value) for key, value in attributes.items()}


class ReadOnlyList(list):  # type: ignore[type-arg]
    """The sequence twin of :class:`ReadOnlyDict`, for the same reason.

    `Principal.attributes` is a `ReadOnlyDict` and its nested containers were plain
    mutable ones, so `who.attributes["tenants"].append("evil-corp")` edited a bound
    trust anchor one level below where the guarantee stopped — the same shape as
    `gate.policy.permissions |= {...}`, which is the finding this class exists to
    close the other half of.

    A `list` subclass rather than a `tuple`, deliberately. A tuple would be the shorter
    answer and it changes the *type* a constraint compares: `Constraint("tenants", "eq",
    value=["acme"])` stops matching the moment the stored value is a tuple, so the fix
    would silently flip authorization verdicts. A list subclass compares equal to a
    list, passes `isinstance`, and serialises the same.
    """

    __slots__ = ()

    def _readonly(self, *_a: Any, **_k: Any) -> Any:
        raise TypeError(
            "this sequence is read-only: it belongs to a Principal that has already been bound, and "
            "editing it would change what a later call is authorized against. Build a new Principal."
        )

    def __setitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __delitem__(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def __iadd__(self, _other: Any) -> Any:  # type: ignore[misc]
        # `xs += [...]` mutates in place and only then rebinds, exactly like the
        # `permissions |= {...}` case: on a frozen owner the rebinding fails and the
        # mutation has already landed.
        self._readonly()

    def __imul__(self, _other: Any) -> Any:  # type: ignore[misc]
        self._readonly()

    def append(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def extend(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def insert(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def pop(self, *_a: Any, **_k: Any) -> Any:
        self._readonly()

    def remove(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def clear(self) -> None:
        self._readonly()

    def sort(self, *_a: Any, **_k: Any) -> None:
        self._readonly()

    def reverse(self) -> None:
        self._readonly()

    def __reduce__(self) -> Any:
        # Built from a plain list rather than replayed through `append`, which
        # `deepcopy` and `pickle` do for a list subclass — and `append` raises here.
        return (self.__class__, (list(self),))

    def copy(self) -> list[Any]:
        return list(self)


def _freeze(value: Any, _seen: frozenset[int] = frozenset()) -> Any:
    """Make an already-copied structure read-only, keeping every subclass it carries.

    Applied after `deepcopy` rather than instead of it, so a `defaultdict` stays a
    `defaultdict` and a `namedtuple` stays a `namedtuple` — only the two plain mutable
    containers, which are the ones a holder can edit into a different authorization
    answer, are swapped for their refusing twins.
    """
    if id(value) in _seen:
        return value
    seen = _seen | {id(value)}
    if type(value) is dict:
        return ReadOnlyDict({k: _freeze(v, seen) for k, v in value.items()})
    if type(value) is list:
        return ReadOnlyList([_freeze(v, seen) for v in value])
    if isinstance(value, (ReadOnlyDict, ReadOnlyList)):
        # Already frozen, and writing to it is what it exists to refuse. This branch was
        # missing and the one below caught it instead, so freezing a structure that had
        # already been frozen — which is exactly what deriving a `Principal` from
        # another one's attributes does — raised out of `__post_init__`. A class whose
        # whole purpose is refusing writes, written to by the function that made it.
        return value
    if isinstance(value, dict):
        # A subclass: keep the type, freeze what is inside it. It stays editable itself,
        # which is the price of not destroying a `Counter`.
        for key, item in list(value.items()):
            value[key] = _freeze(item, seen)
        return value
    if type(value) is tuple:
        return tuple(_freeze(v, seen) for v in value)
    return value


def _thaw(value: Any, _seen: frozenset[int] = frozenset()) -> Any:
    """The inverse of :func:`_freeze`, for the copy a tool is handed.

    Needed because the stored attribute is already frozen and `deepcopy` preserves the
    class — so a handout copied out of the anchor came back refusing the ordinary
    `tenants.append(...)` a tool body does to its own arguments.
    """
    if id(value) in _seen:
        return value
    seen = _seen | {id(value)}
    if isinstance(value, ReadOnlyDict):
        return {k: _thaw(v, seen) for k, v in value.items()}
    if isinstance(value, ReadOnlyList):
        return [_thaw(v, seen) for v in value]
    if isinstance(value, dict):
        for key, item in list(value.items()):
            value[key] = _thaw(item, seen)
        return value
    if type(value) is list:
        return [_thaw(v, seen) for v in value]
    if type(value) is tuple:
        return tuple(_thaw(v, seen) for v in value)
    return value


def _snapshot_value(value: Any, *, readonly: bool = True, _seen: frozenset[int] = frozenset()) -> Any:
    """Deep-copy ``value``, sharing by reference only the leaves that cannot be copied.

    The fallback used to be per *attribute*: `deepcopy(value)`, and on any exception the
    original object was stored whole. That reads as "one uncopyable entry does not cost
    the snapshot on the others" and is true only at the top level. `deepcopy` of a
    container raises if *any* descendant refuses — so a single `threading.Lock` (or an
    open file, a socket, a DB session) anywhere inside `{"tenant": {"id": "acme",
    "lock": Lock()}}` left the whole subtree aliased to the caller's live object,
    including every authorization-relevant scalar in it. A host that then edited its own
    dict flipped a constraint verdict from deny to allow on an already-bound Principal.

    So the walk is structural: containers are rebuilt element by element, and only the
    individual leaf that raises is shared. That leaf is, by the same argument as before,
    one a tool could not mutate into a different authorization answer anyway.

    `deepcopy` is asked *first* all the same, because the structural walk on its own lost
    everything `deepcopy` knows. It has no memo, so a cycle — `d["self"] = d`, which an
    ORM row or a parsed config produces without anyone meaning to — recursed to the
    interpreter limit and the RecursionError escaped `__post_init__`, since the only
    `try` wrapped the leaf copy and not the recursion. And it rebuilt every mapping as a
    plain `dict` and every sequence as `type(value)(items)`, so a `defaultdict` lost its
    factory, `Counter` and `OrderedDict` became `dict`, and a `namedtuple` became a
    plain list. `deepcopy` preserves all of that; the walk is the fallback for the one
    thing it cannot do, which is survive an uncopyable descendant.
    """
    # Read-only on the way down as well as at the top. The snapshot already stopped the
    # *caller's* object being aliased; it left every nested container of the snapshot
    # itself writable, so anyone holding the Principal could still edit a bound trust
    # anchor — `who.attributes["tenants"].append("evil-corp")` — and the next
    # authorization decision read the edit. `_apply_bindings` re-snapshots on the way
    # out, so a tool still receives an ordinary mutable copy.
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        if id(value) in _seen:
            # A cycle. `deepcopy` below would resolve it correctly, and if it is here it
            # has already refused this subtree — so the alias is the honest answer, and
            # it is the same one an uncopyable leaf gets.
            return value
        try:
            copied = deepcopy(value)
        except Exception:  # noqa: BLE001 — fall back to the element-by-element walk
            pass
        else:
            return _freeze(copied) if readonly else _thaw(copied)
        seen = _seen | {id(value)}
        if isinstance(value, dict):
            rebuilt = {
                _snapshot_value(k, readonly=readonly, _seen=seen): _snapshot_value(v, readonly=readonly, _seen=seen)
                for k, v in value.items()
            }
            return ReadOnlyDict(rebuilt) if readonly else rebuilt
        items = [_snapshot_value(v, readonly=readonly, _seen=seen) for v in value]
        if isinstance(value, list):
            return ReadOnlyList(items) if readonly else items
        try:
            return type(value)(items)
        except (TypeError, ValueError):
            # The degradation arm used to re-call the expression that had just raised
            # whenever `type(value)` was one of the base types, so the TypeError came
            # straight back out of `__post_init__`. It fires when an element's own
            # snapshot became unhashable — `frozenset({Point(1, 2)})` is the shape —
            # and sharing the container by reference is the same bargain the leaf
            # branch already makes.
            return value
    try:
        return deepcopy(value)
    except Exception:  # noqa: BLE001 — an uncopyable leaf must not fail the request
        return value
