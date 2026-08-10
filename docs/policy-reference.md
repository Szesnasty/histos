# Policy reference

**Generated from [`spec/policy-0.1.schema.json`](../spec/policy-0.1.schema.json). Do not edit by hand** -
run `python scripts/generate_policy_reference.py` instead, and the suite will tell you if the two ever
drift apart.

Every key in Histos Policy, Draft 0.1, what it does, and whether it is required. For *why* the format has this shape
rather than another, read [`policy-format-draft-0.1.md`](policy-format-draft-0.1.md); for worked examples
at increasing complexity, read [`policies/`](../policies/).

Your editor can show all of this while you type. Put this line at the top of a policy:

```yaml
# yaml-language-server: $schema=https://histos.dev/spec/policy-0.1.schema.json
```

Two rules govern everything below, and they are why the tables are shorter than you might expect:

- **Unknown keys are refused.** Not ignored - refused, at load time. A policy this engine only partly
  understands would enforce only part of what it says.
- **Everything is an allow-list.** There are no deny rules anywhere in the format, because allow *and*
  deny needs a precedence rule, and precedence in authorization is where the CVEs live.

## Top level

The document itself. `policy_id`, `version` and `created_at` are metadata: they identify a policy without changing what it decides, and they are excluded from `content_hash`.

| key | type | required | what it does |
|---|---|---|---|
| `schema_version` | `histos.policy/0.1` (exactly) | **yes** | The FORMAT version. An engine refuses a value it does not implement. |
| `version` | string | no | The ruleset's own revision, chosen by whoever authors the policy. Opaque to the engine; recorded on every audit record. |
| `policy_id` | string | no | A stable name for this policy, for humans and for the audit trail. Metadata: excluded from content_hash, so renaming a policy does not invalidate approvals bound to its hash. |
| `created_at` | string | no | ISO-8601. Set by the exporter; never auto-stamped, so a policy is reproducible. |
| `requires` | mapping | no | Capabilities this policy depends on. An engine that does not implement one MUST refuse the whole policy rather than enforce it partially. This — not an engine version — is the portable contract, because a version number stops meaning anything once more than one engine exists. |
| `canaries` | array of string | no | Planted tokens. Denied verbatim in an argument, redacted from output. A 'prove it' oracle, not exfiltration prevention. |
| `tools` | mapping | **yes** | Keyed by tool name. A mapping, not a list: a repeated tool name is then a duplicate key, which canonical parsing already refuses. |
| `roles` | mapping | no | Keyed by role name. Role-centric rather than inline on the tool, because the reviewable question is 'what can this role do' and because inheritance has no home in the inline form. |

## `tools.<name>`

One entry per tool the policy governs. A tool absent from this mapping is denied with `unknown_tool`; a tool present but granted to nobody is denied with `rbac`. Both refuse the call - only the second shows a reviewer that somebody considered it.

| key | type | required | what it does |
|---|---|---|---|
| `access` | `read` \| `write` | no | 'write' marks a tool whose effects are not undone by not reading the result. Drives review warnings and the IDOR refusal. |
| `sensitivity` | `low` \| `medium` \| `high` \| `critical` | no | How much damage this tool's data or effect represents. Does not change a verdict on its own - it drives review severity, so a high or critical read with no resource constraint is flagged rather than passing silently. Default: low. |
| `rate_limit` | integer | no | Maximum calls per rolling window, per principal. |
| `budget` | integer | no | Maximum total calls, per principal, for the life of the limit store. |
| `args` | mapping | no | The argument contract, and it is deny-by-default: an argument not declared here is REFUSED, not ignored. A gated tool with no args block at all is denied outright rather than waved through. |
| `returns` | mapping | no | The return contract. Names the fields output projection is allowed to keep and gives sensitive-field redaction something to match on. Without it the post-gate has almost nothing to work with. |
| `bind` | mapping | no | Arguments overwritten with trusted principal attributes BEFORE any check runs. This dominates validation: a wrong value becomes un-passable rather than merely detected. Fail-closed if the principal lacks the attribute. |
| `resource` | mapping | no | Row-level authorization: not 'may this role call this tool' but 'may it act on THIS record'. Requires a resource_resolver on the host that fetches the real record; a resolver that echoes an argument re-creates the IDOR this block exists to prevent. |
| `confirmation` | mapping | no | Require a trusted out-of-band approval, bound to this exact tool, arguments and principal, before the call proceeds. Approval is a host callback, never a tool - so an injected agent cannot approve itself. With no callback wired the default is DENY. |
| `escalate` | mapping | no | Route this call to the host's semantic tier - the probabilistic, meaning-level layer this format deliberately does not contain - before it may proceed. The tier can only let a call continue past the deterministic checks it already passed; it can never allow one they refused. With no tier wired the call is DENIED (no_escalation_tier), so adding meaning never weakens the gate and not having it never opens one. |
| `output` | mapping | no | What is allowed to leave the boundary and re-enter the model, including what comes back when the tool raises. |
| `deny_secret_args` | boolean | no | Deny a checksum-verified secret passed as an argument. |

## `args.<name>` and `returns.<name>`

The argument and return contracts. Deny-by-default on the way in: an argument not declared here is refused. On the way out these names are what projection keeps and what sensitive-field redaction matches.

| key | type | required | what it does |
|---|---|---|---|
| `type` | `string` \| `integer` \| `number` \| `boolean` \| `array` \| `object` \| `any` | no | The declared type, checked before the tool runs. 'object' is checked only for BEING an object - inner fields are not validated (see SECURITY.md); validate those inside the tool or keep arguments flat. |
| `required` | boolean | no | Whether the argument must be present. Default: true. A missing required argument is a denial, not a None passed through to the tool. |
| `enum` | array of object | no | The complete set of permitted values. Anything else is denied - this is an allow-list, like every other construct in the format. |
| `min_length` | integer | no | Minimum string length, inclusive. |
| `max_length` | integer | no | Maximum string length, inclusive. The cheapest bound there is on an argument a manipulated model controls. |
| `pattern` | string | no | Compiled at load, so an invalid regex fails loudly. NOT ReDoS-safe: treat patterns imported from third-party schemas as untrusted. |
| `minimum` | number | no | Inclusive lower bound for a number. Expressed in the tool's own units - keep money in minor units so no implementation has to agree about floats. |
| `maximum` | number | no | Inclusive upper bound for a number. This is the ceiling a hijacked model cannot raise, and it belongs here rather than in application code precisely so a reviewer can find it. |
| `exclusive_minimum` | number | no | Exclusive lower bound for a number: the value must be strictly greater. |
| `exclusive_maximum` | number | no | Exclusive upper bound for a number: the value must be strictly less. |
| `multiple_of` | number | no | The number must be an exact multiple of this. Useful for step sizes and whole-unit amounts. |
| `item_type` | `string` \| `integer` \| `number` \| `boolean` \| `object` \| `any` | no | Element type for an array. String elements are bounded by the same length/pattern caps as a scalar string. |
| `sensitive` | `pii` \| `secret` | no | Return schemas only: redacted on the way out unless the principal may view this field. |

## `tools.<name>.resource`

Row-level authorization, evaluated against the record your `resource_resolver` fetched - never against the arguments of the call.

| key | type | required | what it does |
|---|---|---|---|
| `owns` | string or object | no | The IDOR-safe shorthand. 'owns: tenant_id' means: resolve the accessed resource, compare its tenant_id to the principal's tenant_id. A string uses the same name on both sides; the object form maps different names. |
| `where` | array of object | no | Further conditions on RESOLVED resource attributes, e.g. refuse to act on a closed record. Compares against a literal or a trusted principal attribute — never against another argument. |

## `resource.where[]`

A comparison on the resolved resource. Comparisons only: the format is deliberately not an expression language.

| key | type | required | what it does |
|---|---|---|---|
| `field` | string | **yes** | The attribute to read on the RESOLVED resource - the record the resolver fetched, not the arguments of the call. Comparing an argument against itself proves nothing, which is why the format cannot express it. |
| `op` | `eq` \| `ne` \| `in` \| `not_in` \| `le` \| `lt` \| `ge` \| `gt` | **yes** | The comparison. Only comparisons exist: the format is deliberately not an expression language, because an expression language stops being deterministic by construction. |
| `value` | any | no | A literal to compare the resource attribute against. Mutually exclusive with principal_attr. |
| `principal_attr` | string | no | A TRUSTED principal attribute to compare the resource attribute against, bound out-of-band by the host. Mutually exclusive with value. This is the trusted half of the comparison; the attacker supplies the other half and cannot change what the constraint requires. |

## `tools.<name>.confirmation`

Out-of-band human approval, bound to this exact action.

| key | type | required | what it does |
|---|---|---|---|
| `required` | boolean | **yes** | Turn confirmation on for this tool. The gate returns REQUIRE_CONFIRMATION until a trusted approval for this exact action is presented. |
| `expires_in` | integer | no | Seconds an approval stays usable once granted. |

## `tools.<name>.output`

What may leave the boundary and re-enter the model, including what comes back when the tool raises.

| key | type | required | what it does |
|---|---|---|---|
| `project` | boolean | no | Deny-by-default on the return surface: drop any field not declared in 'returns'. A secret in an undeclared field is out of reach of name-based redaction. |
| `strict` | boolean | no | Validate the output against 'returns' and act on a mismatch per on_violation. |
| `on_violation` | `redact_all` \| `deny` \| `allow` | no | What to do when strict returns is on and the result does not match the declared schema. 'redact_all' replaces the whole output, 'deny' refuses the call, 'allow' opts out. Default: redact_all - because name-based redaction cannot protect a secret sitting in a field nobody declared. |
| `scan_canary` | boolean | no | Remove planted canary tokens from the result. Default: true. Verbatim matching only: this is a 'prove it' oracle, not exfiltration prevention. |
| `redact_secrets` | boolean | no | Remove recognised secrets (checksum-verified card numbers, IBANs, decodable JWTs) from anywhere in the result. Default: true. |

## `roles.<name>`

Grants are role-centric because the reviewable question is *what can this role do*, and because role inheritance has nowhere to live in an inline form.

| key | type | required | what it does |
|---|---|---|---|
| `inherits` | string | no | Single parent. Cycle-safe at evaluation; a parent that does not exist is a load error. |
| `allow` | array of string | no | Tools this role may call. Anything not listed is denied. |

## From threat to policy

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
