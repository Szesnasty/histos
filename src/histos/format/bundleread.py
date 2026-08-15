"""The compact spellings a bundle uses, read back into typed contracts.

Split out of `bundle.py`. A document writes `{type: string, max: 64}` where the Python
constructor takes a `Field`, and every one of these readers has the same obligation: a
value it cannot represent is refused loudly, never dropped. A dropped bound produces a
policy that *looks* like it carries the constraint, and the reviewer has no reason to
re-derive it by hand — which is the failure this whole loader exists to prevent.
"""

from __future__ import annotations

from typing import Any

from histos.errors import PolicyError
from histos.format.bundlekeys import (
    _CONDITION_KEYS,
    _CONFIRMATION_KEYS,
    _ESCALATE_KEYS,
    _FIELD_KEYS,
    _OUTPUT_KEYS,
    _PRINCIPAL_REF,
    _RESOURCE_KEYS,
    _TOOL_KEYS,
    _as_list,
    _as_mapping,
    _reject_unknown,
)
from histos.importers.json_schema import schema_from_json_schema
from histos.policy.contracts import Binding, Constraint, Sensitivity, ToolContract
from histos.policy.schema import Field, Schema

# ── field / schema (compact form used inside a bundle) ───────────────────


def _field_from_compact(where: str, spec: Any) -> Field:
    spec = _as_mapping(where, spec)
    _reject_unknown(where, spec, _FIELD_KEYS)
    # A declared `enum` that is not a list must not be silently dropped: the field
    # would read as constrained and accept everything.
    enum = spec.get("enum")
    if enum is not None:
        enum = tuple(_as_list(f"`enum` on {where}", enum))
    # `item_enum` arrived three lines below its twin and without the twin's guard, which
    # is the whole hazard `_as_list` was written for: `item_enum: read` — one missing
    # pair of brackets — became ('r','e','a','d'), so the gate denied `["read"]`, the
    # value the policy says is allowed, and allowed `["r"]`, which it does not.
    item_enum = spec.get("item_enum")
    if item_enum is not None:
        item_enum = tuple(_as_list(f"`item_enum` on {where}", item_enum))
    return Field(
        type=spec.get("type", "string"),
        required=spec.get("required", True),
        enum=enum,
        max_length=spec.get("max_length"),
        min_length=spec.get("min_length"),
        pattern=spec.get("pattern"),
        sensitive=spec.get("sensitive"),
        nullable=spec.get("nullable", False),
        item_enum=item_enum,
        unique_items=spec.get("unique_items", False),
        item_type=spec.get("item_type"),
        max_items=spec.get("max_items"),
        min_items=spec.get("min_items"),
        minimum=spec.get("minimum"),
        maximum=spec.get("maximum"),
        exclusive_minimum=spec.get("exclusive_minimum"),
        exclusive_maximum=spec.get("exclusive_maximum"),
        multiple_of=spec.get("multiple_of"),
    )


def _schema_from_node(where: str, node: Any) -> Schema | None:
    if node is None:
        return None
    node = _as_mapping(where, node)
    # allow an inline standard JSON Schema via {"json_schema": {...}}
    if set(node.keys()) == {"json_schema"}:
        return schema_from_json_schema(_as_mapping(f"`json_schema` in {where}", node["json_schema"]))
    # `$allow_extra` rather than a field named `allow_extra`, so a tool really can have
    # an argument called that. It is the one Schema attribute that is not a field, and
    # it had nowhere to go: `_schema_to_node` emitted only the field map, so a schema
    # imported from `additionalProperties: true` (or inferred from `**kwargs`) came back
    # from a dump/load closed. `histos import --out` therefore wrote a policy that denies
    # arguments the imported source explicitly allows, and `histos import --update` never
    # converged — it re-dumped a different policy every run.
    # Type-checked, not coerced. This loader deliberately strips YAML 1.1's bool
    # resolver so `no`/`off`/`n`/`yes` stay strings, and every other scalar it reads
    # checks loudly — but this one went through `bool()`, and the coercion fails OPEN:
    # `bool("no")` is True, so `$allow_extra: no`, the most natural way to write
    # "closed" in YAML, opened the argument surface.
    raw_allow_extra = node.get("$allow_extra", False)
    if not isinstance(raw_allow_extra, bool):
        raise PolicyError(
            f"`$allow_extra` in {where} must be true or false, got {raw_allow_extra!r} — YAML's "
            "`no`/`off` are ordinary strings in a histos bundle, and any string here would read as "
            "true and open the argument surface"
        )
    allow_extra = raw_allow_extra
    return Schema(
        {
            name: _field_from_compact(f"field {name!r} of {where}", spec)
            for name, spec in node.items()
            if name != "$allow_extra"
        },
        allow_extra=allow_extra,
    )


def _required(where: str, d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise PolicyError(f"{where} is missing the required key {key!r}", code="missing_key")
    return d[key]


def _exact_bool(where: str, value: Any) -> bool:
    """Read a security switch without Python's truthiness coercion."""
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false, got {value!r}", code="invalid_field")
    return value


def _optional_block(where: str, tool: dict[str, Any], key: str) -> dict[str, Any]:
    """Return an absent block as empty, but reject every malformed present block."""
    if key not in tool:
        return {}
    return _as_mapping(where, tool[key])


def _condition_from_dict(name: str, d: Any) -> Constraint:
    where = f"a `resource.where` condition on tool {name!r}"
    d = _as_mapping(where, d)
    _reject_unknown(where, d, _CONDITION_KEYS)
    kwargs: dict[str, Any] = {"field": _required(where, d, "field"), "op": _required(where, d, "op")}
    if "principal_attr" in d:
        kwargs["principal_attr"] = d["principal_attr"]
    if "value" in d:
        kwargs["value"] = d["value"]
    return Constraint(**kwargs)


def _resource_from_dict(name: str, d: Any) -> tuple[Constraint, ...]:
    """Parse the `resource:` block into constraints, `owns` first.

    `owns` is sugar for the row-ownership case and is listed first so a denial names
    ownership before a secondary condition — the answer a reader wants first.
    """
    where = f"the `resource` block on tool {name!r}"
    d = _as_mapping(where, d)
    _reject_unknown(where, d, _RESOURCE_KEYS)
    out: list[Constraint] = []
    owns = d.get("owns")
    if isinstance(owns, str):
        out.append(Constraint.owns(owns))
    elif isinstance(owns, dict):
        owns_where = f"`resource.owns` on tool {name!r}"
        _reject_unknown(owns_where, owns, frozenset({"field", "principal_attr"}))
        out.append(Constraint.owns(_required(owns_where, owns, "field"), _required(owns_where, owns, "principal_attr")))
    elif owns is not None:
        raise PolicyError(f"`resource.owns` on tool {name!r} must be a string or a mapping, got {type(owns).__name__}")
    conditions = _as_list(f"`resource.where` on tool {name!r}", d.get("where", []))
    out.extend(_condition_from_dict(name, c) for c in conditions)
    return tuple(out)


def _bind_from_dict(name: str, d: Any) -> tuple[Binding, ...]:
    """Parse `bind: {field: principal.attr}`.

    The grammar is frozen hard on purpose: exactly ``principal.<identifier>``. A
    binding is a *substitution*, not a language — the moment templating, fallbacks
    (``a ?? b``) or functions are allowed here, the policy stops being decidable by
    inspection and every engine has to agree on an evaluator.
    """
    out: list[Binding] = []
    for arg, ref in _as_mapping(f"the `bind` block on tool {name!r}", d).items():
        if not isinstance(ref, str) or not _PRINCIPAL_REF.fullmatch(ref):
            raise PolicyError(
                f"binding for {arg!r} on tool {name!r} must be exactly 'principal.<attr>', got {ref!r} — "
                "bindings are substitutions, not expressions (no templating, fallbacks or functions)",
                code="invalid_binding",
            )
        out.append(Binding(arg, ref.split(".", 1)[1]))
    return tuple(out)


def _sensitivity_of(name: str, value: Any) -> Sensitivity:
    try:
        return Sensitivity(value)
    except ValueError as exc:
        raise PolicyError(
            f"tool {name!r} declares sensitivity {value!r}; expected one of {', '.join(s.value for s in Sensitivity)}",
            code="invalid_field",
        ) from exc


def _tool_from_dict(name: str, d: Any) -> ToolContract:
    d = _as_mapping(f"tool {name!r}", d)
    _reject_unknown(f"tool {name!r}", d, _TOOL_KEYS)
    confirmation_where = f"`confirmation` on tool {name!r}"
    confirmation = _optional_block(confirmation_where, d, "confirmation")
    _reject_unknown(confirmation_where, confirmation, _CONFIRMATION_KEYS)
    if "confirmation" in d:
        confirmation_required = _exact_bool(
            f"`confirmation.required` on tool {name!r}", _required(confirmation_where, confirmation, "required")
        )
    else:
        confirmation_required = False

    escalate_where = f"`escalate` on tool {name!r}"
    escalate = _optional_block(escalate_where, d, "escalate")
    _reject_unknown(escalate_where, escalate, _ESCALATE_KEYS)
    if "escalate" in d:
        escalation_required = _exact_bool(
            f"`escalate.required` on tool {name!r}", _required(escalate_where, escalate, "required")
        )
    else:
        escalation_required = False

    output_where = f"`output` on tool {name!r}"
    output = _optional_block(output_where, d, "output")
    _reject_unknown(output_where, output, _OUTPUT_KEYS)

    resource = _optional_block(f"the `resource` block on tool {name!r}", d, "resource")
    bindings = _optional_block(f"the `bind` block on tool {name!r}", d, "bind")
    return ToolContract(
        name=name,
        args=_schema_from_node(f"`args` on tool {name!r}", d.get("args")),
        returns=_schema_from_node(f"`returns` on tool {name!r}", d.get("returns")),
        access=d.get("access", "read"),
        sensitivity=_sensitivity_of(name, d.get("sensitivity", "low")),
        rate_limit=d.get("rate_limit"),
        budget=d.get("budget"),
        requires_confirmation=confirmation_required,
        confirmation_expires_in=confirmation.get("expires_in"),
        requires_escalation=escalation_required,
        constraints=_resource_from_dict(name, resource),
        bindings=_bind_from_dict(name, bindings),
        scan_output_for_canary=_exact_bool(f"`output.scan_canary` on tool {name!r}", output.get("scan_canary", True)),
        deny_secret_args=_exact_bool(f"`deny_secret_args` on tool {name!r}", d.get("deny_secret_args", True)),
        redact_secret_output=_exact_bool(
            f"`output.redact_secrets` on tool {name!r}", output.get("redact_secrets", True)
        ),
        project_output=_exact_bool(f"`output.project` on tool {name!r}", output.get("project", False)),
        strict_returns=_exact_bool(f"`output.strict` on tool {name!r}", output.get("strict", False)),
        on_output_violation=output.get("on_violation", "redact_all"),
    )
