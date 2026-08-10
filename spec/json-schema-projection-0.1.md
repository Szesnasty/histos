# JSON Schema → tool contract, projection 0.1

**Normative.** This document defines what an implementation must produce when it
imports a JSON Schema object as a tool contract, and therefore what
`contract_sha256` in [`tool-lock-0.1.schema.json`](tool-lock-0.1.schema.json) is
computed over.

It is normative because drift detection is a *comparison*. If a Python bridge carries
`minLength` and a TypeScript one does not, the same tool drifts in one runtime and not
the other, and the signal turns into noise people learn to ignore. A subset is fine —
this one is deliberately small — but it has to be the *same* subset everywhere.

MCP, OpenAI tool definitions and OpenAPI all carry JSON Schema for their arguments,
so this single mapping covers every source kind.

## The mapping

| JSON Schema | contract field | notes |
|---|---|---|
| `type` | `type` | one of `string`, `integer`, `number`, `boolean`, `array`, `object`; anything else becomes `any` |
| `type: [T, "null"]` | `type` = T, and `required` = false | a nullable field is an optional field |
| listed in `required[]` | `required` | absent from the list → `required: false` |
| `enum` | `enum` | order preserved as written |
| `minLength` | `min_length` | |
| `maxLength` | `max_length` | |
| `pattern` | `pattern` | matched with full-string semantics at enforcement time |
| `minimum` | `minimum` | |
| `maximum` | `maximum` | |
| `exclusiveMinimum` | `exclusive_minimum` | **numeric form only** (draft 6+) |
| `exclusiveMaximum` | `exclusive_maximum` | **numeric form only** (draft 6+) |
| `multipleOf` | `multiple_of` | |
| `items.type` | `item_type` | element type for arrays; nested item schemas are not projected |
| `x-sensitive` | `sensitive` | `"pii"` or `"secret"`, on a *return* schema; any other value is dropped |
| `additionalProperties: true` | `allow_extra` = true | see below |

Everything else in the source document is **not projected**: `$ref` targets beyond
one local level, `allOf`/`anyOf`/`oneOf`, nested object schemas, `format`,
`default`, `title`, `examples`. A key that is not in the table above must not affect
the contract, and therefore must not affect `contract_sha256`.

## Two places where the projection is deliberately not a faithful copy

**`additionalProperties` defaults to closed.** JSON Schema's default is permissive;
this is a policy artifact, so the argument surface is deny-by-default and an
undeclared argument is refused. Only an explicit `additionalProperties: true` opens
it. An implementation that inherits JSON Schema's default here produces a policy that
silently accepts arguments nobody declared.

**Draft-4's boolean `exclusiveMinimum` / `exclusiveMaximum` is ignored, not
converted.** In draft 4 those were booleans modifying `minimum` / `maximum`. Reading
`exclusiveMinimum: true` as the number 1 would invent a bound nobody wrote, so a
non-numeric value is dropped.

## Numbers

Every number reaching a lock hash is first rendered as a decimal string:

- integral values → integer form, no fractional part: `1`, `500`, `-3`
- everything else → shortest round-trip form: `0.5`, `0.01`

This exists because the canonical serializer is type-tagged, so Python's `1` and
`1.0` would otherwise hash differently — a distinction `JSON.parse` cannot even see.
Rendering to text first removes information the source never carried.

**Limit of the guarantee in version 1:** values whose shortest round-trip form uses
exponent notation are not guaranteed to render identically across languages
(`1e-07` in Python, `1e-7` in JavaScript). Policy bounds are amounts, lengths and
counts, so this is a corner rather than a case — but it is a corner, and it is named
here rather than discovered later.

## What `contract_sha256` covers

`canonical_json` of exactly this structure, with numbers rendered as above:

```
{
  "args":    <schema fingerprint, or null>,
  "returns": <schema fingerprint, or null>
}
```

where a schema fingerprint is:

```
{
  "allow_extra": bool,
  "fields": {
    "<name>": {
      "type", "required", "enum", "max_length", "min_length", "pattern",
      "sensitive", "item_type", "minimum", "maximum",
      "exclusive_minimum", "exclusive_maximum", "multiple_of"
    }
  }
}
```

Every key is always present, with `null` where unset — an implementation must not
omit empty ones, or the two hashes diverge on absence.

Key order does not matter: `canonical_json` sorts object entries by their
canonicalised key.

**Excluded on purpose:** `access`, `sensitivity`, `rate_limit`, `budget`,
`confirmation`, `resource` constraints, `bind`, and every `output` rule. Those are the
security semantics a human writes, and no schema supplies them. Adding an ownership
rule is not tool drift, and must not be reported as such.
