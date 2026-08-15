"""Infer an argument schema from a Python function's signature + type hints.

Requiring a hand-written ``arg_schema`` for 25 tools is adoption death. The
highest-leverage feature is not an authoring UI — it is automatic contract import,
so a developer runs ``protect(tools)`` and gets "23/25 recognised; 2 need a
decision".

**Honest scope.** A signature yields the *schema skeleton* — argument names,
types, which are required — nothing more. It does **not** yield the security
policy: RBAC grants, resource constraints and return-field sensitivity still
need a human. So inference closes the *schema* gap, never the *authorization*
gap. ``protect()`` reflects that in its coverage report.

Stdlib only (``inspect`` + ``typing``). Pydantic / OpenAPI / MCP importers are
follow-ups that produce the same :class:`~histos.policy.contracts.ToolContract`.
"""

from __future__ import annotations

import enum
import inspect
import types
import typing
from collections.abc import Callable
from typing import Any

from histos.policy.contracts import ToolContract
from histos.policy.schema import Field, Schema

_PY_TO_SCHEMA: dict[type, str] = {
    int: "integer",
    str: "string",
    float: "number",
    bool: "boolean",
    list: "array",
    tuple: "array",
    dict: "object",
}


def _map_annotation(ann: Any) -> tuple[str, bool, str | None]:
    """Return ``(schema_type, optional, item_type)`` for a type annotation."""
    if ann is inspect.Parameter.empty or ann is None:
        return "any", False, None

    origin = typing.get_origin(ann)
    args = typing.get_args(ann)

    # Optional[X] / Union[..., None] / X | None
    is_union = origin is typing.Union or isinstance(ann, types.UnionType)
    if is_union:
        non_none = [a for a in args if a is not type(None)]
        optional = len(non_none) < len(args)
        if len(non_none) == 1:
            t, _opt, item = _map_annotation(non_none[0])
            return t, optional, item
        return "any", optional, None

    if origin in (list, tuple):
        item_type = _map_annotation(args[0])[0] if args else None
        return "array", False, item_type

    if isinstance(ann, type):
        if issubclass(ann, enum.Enum):
            return _enum_type(ann), False, None
        if ann in _PY_TO_SCHEMA:
            return _PY_TO_SCHEMA[ann], False, None

    return "any", False, None


def _enum_type(ann: type[enum.Enum]) -> str:
    """The schema type an Enum's *values* actually have.

    Assuming ``string`` built an unsatisfiable field for an ``IntEnum``: the type said
    string, the enum listed integers, and no value could ever be both — so the tool was
    dead on arrival with an `arg_schema` denial nobody could read a cause out of.
    Anything mixed degrades to `any` with no enum rather than to a contradiction; a
    schema that cannot be satisfied is worse than one that does not constrain, because
    the second is visible in `histos review` and the first looks like a working policy.
    """
    if issubclass(ann, enum.Flag):
        # A Flag's satisfiable values are the closure under `|`, not the members: listing
        # the members denies every composed value, which is the whole point of a Flag.
        # Its own rule applies — an enum that cannot be listed honestly is not listed.
        return "integer" if all(isinstance(m.value, int) for m in ann) else "any"
    values = [member.value for member in ann]
    if values and all(isinstance(v, bool) for v in values):
        return "boolean"
    if values and all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        return "integer"
    if values and all(isinstance(v, str) for v in values):
        return "string"
    if values and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values):
        return "number"
    return "any"


def infer_schema(func: Callable[..., Any]) -> Schema:
    """Infer a :class:`~histos.policy.schema.Schema` from ``func``'s signature.

    An annotation this process cannot resolve — a ``TYPE_CHECKING``-only import, a
    forward reference to a name that is not importable at runtime — degrades that
    argument to ``any``. The degradation is deliberate but must never masquerade as
    validation: ``Gate.protect`` refuses to install a schema that constrains nothing
    (``_schema_constrains``), so a fully degraded tool keeps its ``no_arg_schema``
    denial, and ``review_policy`` warns about a partly degraded one.
    """
    try:
        hints = typing.get_type_hints(func)
    except (NameError, AttributeError, TypeError):
        # Exactly the three an unresolvable annotation raises. A wider catch turned a
        # genuine bug in this module into a silent all-`any` schema.
        hints = {}
    sig = inspect.signature(func)

    fields: dict[str, Field] = {}
    allow_extra = False
    for pname, param in sig.parameters.items():
        if pname in ("self", "cls"):
            continue
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            allow_extra = True  # **kwargs → cannot schema precisely
            continue
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            continue
        ann = hints.get(pname, param.annotation)
        ftype, optional, item_type = _map_annotation(ann)
        required = param.default is inspect.Parameter.empty and not optional

        enum_vals: tuple[Any, ...] | None = None
        if isinstance(ann, type) and issubclass(ann, enum.Enum) and not issubclass(ann, enum.Flag) and ftype != "any":
            # Dropped along with the type when the members disagree: listing values the
            # declared type cannot hold is the contradiction `_enum_type` exists to avoid.
            enum_vals = tuple(e.value for e in ann)

        fields[pname] = Field(type=ftype, required=required, item_type=item_type, enum=enum_vals, nullable=optional)

    return Schema(fields, allow_extra=allow_extra)


def infer_contract(func: Callable[..., Any], **overrides: Any) -> ToolContract:
    """Build a schema-only :class:`ToolContract` from ``func`` (override the rest)."""
    name = overrides.pop("name", None) or getattr(func, "__name__", None)
    if not name:
        raise ValueError("cannot determine tool name for inference; pass name=")
    args = infer_schema(func)
    return ToolContract(name=name, args=args, **overrides)
