#!/usr/bin/env python3
"""Generate `docs/policy-reference.md` from `spec/policy-0.1.schema.json`.

The schema is the single source of truth for what every key means. Writing the
reference by hand would create a second one, and two sources of truth for a
security format is how a document ends up describing a field the engine renamed
two releases ago.

Run after changing the schema:

    python scripts/generate_policy_reference.py

`tests/test_policy_reference_is_current.py` fails if the committed document and
the schema have drifted, so this cannot be forgotten quietly.
"""

from __future__ import annotations

import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPOSITORY_ROOT / "spec" / "policy-0.1.schema.json"
OUTPUT_PATH = REPOSITORY_ROOT / "docs" / "policy-reference.md"

# Order and framing for each block, so the document reads as a walk through a
# policy rather than an alphabetical dump of definitions.
SECTIONS: list[tuple[str, str, str]] = [
    (
        "root",
        "Top level",
        "The document itself. `policy_id`, `version` and `created_at` are metadata: they identify a "
        "policy without changing what it decides, and they are excluded from `content_hash`.",
    ),
    (
        "tool",
        "`tools.<name>`",
        "One entry per tool the policy governs. A tool absent from this mapping is denied with "
        "`unknown_tool`; a tool present but granted to nobody is denied with `rbac`. Both refuse the "
        "call - only the second shows a reviewer that somebody considered it.",
    ),
    (
        "field",
        "`args.<name>` and `returns.<name>`",
        "The argument and return contracts. Deny-by-default on the way in: an argument not declared "
        "here is refused. On the way out these names are what projection keeps and what "
        "sensitive-field redaction matches.",
    ),
    (
        "resource",
        "`tools.<name>.resource`",
        "Row-level authorization, evaluated against the record your `resource_resolver` fetched - "
        "never against the arguments of the call.",
    ),
    (
        "condition",
        "`resource.where[]`",
        "A comparison on the resolved resource. Comparisons only: the format is deliberately not an "
        "expression language.",
    ),
    (
        "confirmation",
        "`tools.<name>.confirmation`",
        "Out-of-band human approval, bound to this exact action.",
    ),
    (
        "output",
        "`tools.<name>.output`",
        "What may leave the boundary and re-enter the model, including what comes back when the tool raises.",
    ),
    (
        "role",
        "`roles.<name>`",
        "Grants are role-centric because the reviewable question is *what can this role do*, and "
        "because role inheritance has nowhere to live in an inline form.",
    ),
]


def resolve(node: dict, schema: dict) -> dict:
    """Follow a single `$ref` so the table shows the referenced shape, not the pointer."""
    reference = node.get("$ref")
    if not reference:
        return node
    target = schema
    for part in reference.removeprefix("#/").split("/"):
        target = target[part]
    return {**target, **{k: v for k, v in node.items() if k != "$ref"}}


def describe_type(prop: dict, schema: dict) -> str:
    """A human-readable type cell: allowed values where they are closed, otherwise the type."""
    resolved = resolve(prop, schema)

    if "const" in resolved:
        return f"`{resolved['const']}` (exactly)"

    if enum := resolved.get("enum"):
        return " \\| ".join(f"`{value}`" for value in enum)

    declared = resolved.get("type")
    if declared == "array":
        item = resolve(resolved.get("items", {}), schema)
        item_type = item.get("type") or "object"
        return f"array of {item_type}"
    if declared == "object" and "additionalProperties" in resolved:
        return "mapping"
    if isinstance(declared, list):
        return " \\| ".join(declared)
    if declared:
        return str(declared)

    if "oneOf" in resolved or "anyOf" in resolved:
        return "string or object"
    return "any"


def render_block(name: str, title: str, intro: str, schema: dict) -> str:
    definition = schema if name == "root" else schema["$defs"][name]
    properties: dict = definition.get("properties") or {}
    required: set[str] = set(definition.get("required") or [])

    lines = [f"## {title}", "", intro, "", "| key | type | required | what it does |", "|---|---|---|---|"]

    for key, prop in properties.items():
        resolved = resolve(prop, schema)
        description = (resolved.get("description") or "").replace("|", "\\|").replace("\n", " ")
        marker = "**yes**" if key in required else "no"
        lines.append(f"| `{key}` | {describe_type(prop, schema)} | {marker} | {description} |")

    return "\n".join(lines)


def build() -> str:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    version = schema.get("title", "Histos Policy")

    header = f"""# Policy reference

**Generated from [`spec/policy-0.1.schema.json`](../spec/policy-0.1.schema.json). Do not edit by hand** -
run `python scripts/generate_policy_reference.py` instead, and the suite will tell you if the two ever
drift apart.

Every key in {version}, what it does, and whether it is required. For *why* the format has this shape
rather than another, read [`policy-format-draft-0.1.md`](policy-format-draft-0.1.md); for worked examples
at increasing complexity, read [`policies/`](../policies/).

Your editor can show all of this while you type. Put this line at the top of a policy:

```yaml
# yaml-language-server: $schema=https://usehistos.dev/spec/policy-0.1.schema.json
```

Two rules govern everything below, and they are why the tables are shorter than you might expect:

- **Unknown keys are refused.** Not ignored - refused, at load time. A policy this engine only partly
  understands would enforce only part of what it says.
- **Everything is an allow-list.** There are no deny rules anywhere in the format, because allow *and*
  deny needs a precedence rule, and precedence in authorization is where the CVEs live.

## The Python names and the file names

`Policy(...)` in code and a policy on disk are the same ruleset, and three things are spelled
differently in each. The file format is the versioned, published one, so it is the spelling the loader
accepts; the constructor keeps the names that read better as Python keyword arguments. Writing a Python
name into a file is refused by name, with this table cited.

| in `Policy(...)` | in the file |
|---|---|
| `permissions={{"support": frozenset({{"get_order"}})}}` | `roles: {{support: {{allow: [get_order]}}}}` |
| `role_inherits={{"admin": "support"}}` | `roles: {{admin: {{inherits: support}}}}` |
| `policy_version="3"` | `version: "3"` |
"""

    schema_dict = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    blocks = [render_block(name, title, intro, schema_dict) for name, title, intro in SECTIONS]

    footer = r"""## From threat to policy

The tables above answer "what does this key do". This section answers the question that
arrives first: *"my agent can do something dangerous - which lines stop it?"* Each row
names a failure mode real production agents have, and the construct that bounds it.
Every recipe is worked in full in the gallery and is checkable with `histos explain`.

| the agent can... | the risk | the bound | keys | shown in |
|---|---|---|---|---|
| email arbitrary recipients | read a secret here, send it there - a full exfiltration path | recipient must fully match a pattern; `re.fullmatch` makes `"ok@corp.com, evil@x.com"` one non-matching string | `pattern`, `max_length` | `06` |
| accept new fields on a send | smuggle `bcc` / `reply_to` past review | an undeclared argument is refused, not ignored | declare only what is allowed in `args` | `06` |
| put a secret in a body | leak a card number or token in free text | checksum-verified secrets denied on the way in, redacted on the way out | `deny_secret_args`, `output.redact_secrets` | `06` |
| act on data it retrieved | a poisoned document steers a real action | plant a token; a send that carries it dies | `canaries`, `output.scan_canary` | `03`, `06` |
| deploy to production | an irreversible action in the wrong place | make the dangerous value one the format cannot express on this tool | `enum` without it | `07` |
| deploy a moving ref | `latest` / a branch changes meaning after review | require a pinned version or a full sha | `pattern` on the version | `07` |
| act during a change freeze | override an operational lock | check the resource's REAL current state | `resource.where`, `op: eq` | `07` |
| scale a service to zero | take a service down through a "safe" tool | a numeric floor is an availability control | `minimum` | `07` |
| touch another tenant's record | cross-tenant read or write (IDOR) | resolve the accessed record, compare its true owner | `resource.owns` + a real resolver | `02`, `05` |
| pass a handle it never received | an invented ID, or one an attacker's document supplied | do not track where the ID came from - resolve it. It dies if it does not exist (`resource_not_found`) or is not theirs | `resource.owns` + a real resolver | `02`, `06` |
| pass its own `tenant_id` | self-declared authorization proves nothing | overwrite it from trusted identity before any check | `bind` | `02`, `04` |
| repeat a legal call | forty legal refunds are still forty refunds | cap the count per principal | `budget`, `rate_limit` | `04`, `06` |
| act above a threshold | an amount inside policy but above sense | a human, out-of-band, bound to this exact call | `confirmation` | `04`, `06`, `07` |
| return more than it should | a secret in an undeclared return field | keep only declared fields, redact the rest | `output.project`, `output.strict`, `sensitive` | `03`, `04` |

Two patterns run through the whole table and deserve stating on their own.

**Conditional policy is expressed by splitting the tool.** The format has no
if-expressions, on purpose. "May send internally freely, externally only with approval"
is not a condition - it is `send_email` and `send_email_external`, two tools with
different grants and different friction. Same for `deploy_service` (dev/staging) versus
`deploy_production`. You get conditionals by declaring two bounded tools, not one
flexible one.

**Make undo cheaper than do.** In `07-devops-deploy`, every `deploy_*` needs
confirmation and `rollback_service` does not. Asymmetric friction puts the cost on the
dangerous direction, so incident response gets faster exactly when deployment gets
slower.

## What you cannot write

Named so nobody designs around their absence:

- **no expressions** - comparisons only, against a literal or a trusted principal attribute;
- **no deny rules** - allow-lists only;
- **no multiple inheritance** - one parent per role;
- **no nested object schemas** - a `type: object` argument is checked for being an object, not for its
  contents;
- **no per-environment overlays** - that is policy lifecycle, not policy;
- **no external references** - a policy contains the tool shapes it enforces; it never points at
  one. `histos import` writes them in for you, so nothing is hand-copied, but the written result is
  what gets hashed and shipped. A reference would mean the same `content_hash` could decide
  differently in two places, and it would let the *tool* declare which of its own arguments are
  legal - the wrong way round when the tool is the thing you are bounding;
- **no call-sequence constraints** - a decision is made one call at a time, from the principal, the
  tool, its arguments and the resolved resource. The only thing carried across calls is a *counter*
  (`rate_limit`, `budget`) - never a history of which calls happened, or in what order. *"No
  `send_email` after `read_secret`"*, or *"this argument must be something an earlier tool returned"*,
  cannot be written. Two deterministic constructs cover the cases that
  actually bite: a **canary** is exact-match taint on one specific value - redacted on the way out, a
  hard DENY on the way in - and a **handle is re-resolved**, not remembered, so an invented ID dies as
  `resource_not_found` and somebody else's dies as `resource_constraint`. General propagation across
  free text loses to paraphrase and re-encoding, so it belongs to the semantic tier;
- **no semantic judgement** - "is this action sensible" is permanently a different tier.
"""

    return header + "\n" + "\n\n".join(blocks) + "\n\n" + footer


if __name__ == "__main__":
    OUTPUT_PATH.write_text(build(), encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPOSITORY_ROOT)}")
