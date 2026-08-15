# Where tool shapes come from, and how drift is caught

**Status: shipped 2026-08-10.** `histos import` writes a lock, `histos drift` fails CI
on a changed tool definition, and `histos import --update` refreshes the contract
surface without touching the security semantics. The normative pieces are
[`spec/tool-lock-0.1.schema.json`](../spec/tool-lock-0.1.schema.json) and
[`spec/json-schema-projection-0.1.md`](../spec/json-schema-projection-0.1.md), with a
`projection/` corpus in `conformance/` so a second implementation cannot import the
same definition differently.

## The question

A tool already has a schema. MCP publishes one through `tools/list`, OpenAPI has one,
so do Pydantic and Zod. If a policy also contains argument types, does a team now
maintain the same schema twice?

The complaint behind that question is fair and will keep arriving, so this document
answers it once, in the form it will be asked: *"why am I rewriting my Zod schema into
your YAML?"*

## What is already true

**You are not rewriting it.** `histos import <source> --kind mcp` reads the tool
definitions and writes the policy skeleton, arguments and all. Nobody hand-copies a
type.

**One reason people believed otherwise was a real defect, now fixed.** The JSON Schema
bridge mapped `enum`, `maxLength`, `pattern` and `items.type` but silently dropped
`minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf` and
`minLength` — even though `Field` carries all of them and the engine enforces them. So
importing a schema that said `amount: {minimum: 1, maximum: 10000}` produced an
unbounded integer, and the only way to get the bound back was to type it in by hand.
That is exactly the "two schemas" experience, and it was our bug rather than a
property of the design. Fixed, with an end-to-end test asserting that an imported
bound refuses a real call.

## What is actually missing

Three things, and only the first is what people mean when they complain.

1. **There is no second import.** Once generated, the policy is frozen. If the server
   adds an argument, widens a bound or rewrites a description, nothing says so.
2. **Re-importing would clobber hand-written policy.** The valuable half of a policy —
   roles, `resource.owns`, `bind`, `confirmation`, `output` — cannot be inferred from
   any schema and is added by a human afterwards. A naive regeneration destroys it.
3. **The description does not enter the enforcement contract.** Import records it and
   every other source field as provenance, while `contracts_from_mcp` projects only the
   enforceable shape. A description is where a tool-poisoning payload hides, so *"the
   contract did not change"* is not the same claim as *"the tool definition did not
   change"*.

## The principle

> **The contract describes the tool. The policy constrains its use.**
> Histos imports the first, and hashes both.

Security semantics are never inferred. A schema can tell you `amount` is an integer;
nothing in it can tell you a refund needs approval, or that `order_id` must belong to
the caller's tenant. Import fills in the shape; a human fills in the boundary.

## It has to behave identically in every runtime

Python and TypeScript, MCP and OpenAPI and OpenAI tool definitions, Pydantic and Zod.
That constraint decides what is **normative** and what is merely an implementation's
convenience, and it is worth settling before any code is written.

**Normative — belongs in `spec/`, with conformance cases:**

- the lock file schema and its canonicalisation;
- the three hash definitions, exactly enough that two implementations agree byte for
  byte;
- **the JSON Schema → contract projection**, which is the part that is easy to get
  wrong.

That last one is a real change in status. Today the mapping is a documented subset in
a Python docstring — a convenience. The moment `contract_sha256` is a cross-runtime
claim it becomes a contract: if the Python bridge carries `minLength` and a TypeScript
bridge does not, then the same tool drifts in one runtime and not in the other, and
the whole mechanism reports noise. The conformance manifest already says *"a second
implementation reads this file"*, so the corpus is the right home: a set of
`(source schema → expected contract → expected contract_sha256)` cases that any
implementation must reproduce.

This also reframes the bound-dropping defect fixed above. It was not only bad DX — it
was a projection divergence waiting to happen, in the one place where divergence
turns a security signal into a false alarm.

**Per implementation — not normative:** the commands, their flags and their output.
`histos drift` is a Python CLI; a TypeScript runtime ships its own equivalent. They
interoperate through the lock file, not through each other.

### Two kinds of source, and they drift differently

| | document sources | code sources |
|---|---|---|
| examples | MCP `tools/list`, OpenAPI, OpenAI tool definitions | Pydantic models, Zod schemas, a Python signature |
| the source is | fetchable, and readable by any implementation | a module inside the host process |
| who can check drift | any runtime, any language, from a CLI | only the host runtime, in-process |
| where the check runs | CI, against the endpoint or document | application start-up, or the project's own test suite |

The lock entry has the same shape either way; what differs is who is able to compute
the hash. A code source is inherently language-bound — Zod is TypeScript, Pydantic is
Python — so a Python CLI cannot verify a Zod-defined tool and must not pretend it can.
It reports that tool as *unverifiable from here*, which is the same discipline as the
honest-limits section below.

**OpenAI tool definitions** are the cheapest importer to add: the `parameters` object
is JSON Schema, so the existing bridge does the work. One interaction to note — OpenAI
strict mode requires `additionalProperties: false` with every property listed in
`required`, and Histos is already closed-by-default on the argument surface. Strict
definitions therefore import unchanged, and a non-strict one still imports *closed*,
which is the safe direction to disagree in.

## Options considered

### A. A live reference — `contract: mcp:make_refund`

Rejected. It breaks two load-bearing properties at once.

- **The artifact stops being self-contained.** The same `content_hash` could enforce
  differently in two places, because the effective policy depends on something outside
  the hashed document. Reproducible decisions are the basis of everything in
  [`open-core-boundary.md`](open-core-boundary.md); this trades that away for typing
  convenience.
- **The tool would declare which of its own arguments are legal.** Deny-by-default on
  undeclared arguments is a control aimed *at the tool*. A compromised MCP server adds
  `include_sensitive_data` to its own schema and the gate imports it as permitted.
  This is not hypothetical: a published MCP package shipped clean releases and then
  added email-exfiltration code.

### B. A provenance block inside the policy — `tools.<name>.source: {...}`

Rejected, less emphatically. It works, but it costs more than it returns.

`_reject_unknown` refuses any key this engine does not understand, so a new key means
older engines refuse policies that carry it — fail-closed, therefore safe, but a
compatibility break bought for build metadata. It also needs schema, conformance and
reference-doc changes, and it puts bytes into a security artifact that deliberately do
not affect what the artifact decides. `Policy.fingerprint()` is an allow-list, so
excluding them from the hash is easy — which is precisely the problem: the file would
carry two kinds of content, only one of which is hashed.

### C. A sidecar lock file — **chosen**

`security.policy.lock.json` beside the policy. Nothing in the format changes, no
compatibility is broken, no hash question arises, and the policy stays exactly the
portable artifact it is meant to be. Provenance is build metadata, and build metadata
belongs in a lock file — the precedent is every package manager in use.

## The lock file

One entry per tool that came from an importable source, carrying **three** hashes
because they answer three different questions.

```json
{
  "lock_version": 1,
  "policy": "security.policy.yaml",
  "tools": {
    "make_refund": {
      "source": { "kind": "mcp", "locator": "http://tools.internal/mcp" },
      "schema_sha256":      "…",
      "description_sha256": "…",
      "contract_sha256":    "…"
    }
  }
}
```

| hash | over | the question it answers |
|---|---|---|
| `schema_sha256` | the raw `inputSchema` / `outputSchema`, canonicalised | did the tool's declared shape change at all? |
| `description_sha256` | the description string | did the prose change? It never reaches the contract, and it is where a poisoning payload hides |
| `contract_sha256` | the imported `ToolContract` projection | did the change reach the part the policy enforces? |

The third exists because our import is a deliberate subset: a source change that does
not alter the projection is worth *reporting* but is not the same event as one that
does. Microsoft's MCP gateway keeps `schema_hash` and `description_hash` for the same
reason; the projection hash is ours because our mapping is lossy on purpose.

Reuse `histos.canonical.canonical_json` so a re-serialised source hashes identically.

## The commands

```bash
histos import <source> --kind mcp --out security.policy.yaml   # also writes the lock
histos drift  security.policy.yaml                             # CI gate
histos import <source> --kind mcp --update security.policy.yaml
```

**`histos drift`** re-reads the source, recomputes the three hashes, compares with the
lock, and exits non-zero on any difference. Output names the tool, which hash moved,
and what the change was:

```
DRIFT  make_refund
  schema      + argument `include_sensitive_data` (boolean)
  contract    changed — this reaches enforcement
  description unchanged

1 tool drifted, 1 reaching enforcement.
```

A new argument on a tool is a security event, not a merge conflict. It fails.

**`--update`** regenerates **only** `args` and `returns` for the named tools and leaves
`access`, `sensitivity`, `resource`, `bind`, `confirmation`, `output`, `budget`,
`rate_limit` and the whole `roles` block untouched, then refreshes the lock. Those keys
are separable in the tool block, so the merge is mechanical rather than clever.

It writes; it does not ask. **git is the review** — the diff is what a human approves,
which is consistent with the position that policy lifecycle should lean on the tooling
teams already own rather than reinvent it.

## Honest limits

- **A green `drift` does not mean every tool was verified.** Tools with no recorded
  source — hand-written, or inferred from a Python signature — are not covered, and
  the command must say so in its summary rather than imply coverage it does not have.
- **A deleted or absent lock is not a pass.** No baseline is its own reported state,
  never silence.
- **`description_sha256` detects change; it does not judge content.** Deciding whether
  a new description is an injection attempt is semantic work and stays in the other
  tier. The deterministic claim is only *"this text is not the text you reviewed."*
- **Drift detection is not authentication of the source.** Reading `tools/list` over
  the network trusts the transport and whatever identity the host established. This
  catches a definition that changed since you reviewed it; it does not establish who
  is answering.

## What this is deliberately not

- Not a live contract reference (option A, and why).
- Not schema inference of security semantics. Roles, ownership, binding, approval and
  output rules never come from an import — see the principle above.
- Not a second source of truth. The policy remains the artifact; the lock records
  where the imported half came from and what it looked like when a human last read it.

## What shipped, and the one thing that surprised us

Everything above, plus a cross-language hazard the implementation surfaced.

`canonical_json` is **type-tagged**, so Python serialises `1` as `["i",1]` and `1.0`
as `["f","1.0"]` — two different hashes for a bound most people would call the same.
Python knows which one the document wrote because `json.loads` keeps the distinction;
**JavaScript does not**, because `JSON.parse` collapses both to one number. A schema
saying `minimum: 1.0` would therefore have drifted in a TypeScript runtime and not in
this one, for no reason a user could ever diagnose.

Fixed by rendering every number as a decimal string before it reaches a lock hash, so
the tag stops carrying information the source never had. The fix is confined to the
lock layer on purpose: `Policy.content_hash` has the same shape of exposure, but
changing it would invalidate every published policy hash and every canonicalization
fixture. That is a `schema_version` decision, not a side effect of adding drift
detection, and it is recorded in [`tech-debt.md`](tech-debt.md).

Worth noting where the concern was already written down: the canonicalization corpus
has said from the start that engines *"diverge on whether 1.0 and 1 hash the same, and
then approvals bound to a policy hash quietly stop matching between services."* The
corpus was right; it just had not been applied to the import path yet.

## Sequencing

Ships with the MCP product flow, not after it — `roadmap.md` already refuses to treat
the adapter and its DX as two deliverables, and a drift check is part of what makes an
imported policy trustworthy over time.

The normative pieces come first, because they are what allows a second runtime to
exist at all and they are far harder to change once a lock file is in somebody's
repository:

1. **`spec/`** — the lock file schema, the three hash definitions, and the JSON Schema
   → contract projection written down as a mapping table rather than a docstring
   — **done**;
2. **conformance** — a projection corpus: source schema → expected contract →
   expected `contract_sha256`, which any implementation must reproduce — **done**,
   the versioned corpus named in `conformance/manifest.json`;
3. lock file written by `import` — **done**;
4. `histos drift` reading it, with the three-hash report and a non-zero exit —
   **done**;
5. `--update` with the args/returns-only merge — **done**, and it refuses to rewrite
   a commented policy rather than silently dropping the comments;
6. `--kind openai`, and OpenAPI, which records a document locator rather than an
   endpoint — **done**;
7. **in-process drift for code sources — not built.** Pydantic and Zod models live in
   the host process, so this arrives with each language's own runtime rather than in
   the CLI. Until it exists, `histos drift` reports such tools as *unverifiable from
   here*, which is the honest state and not a silent pass.

Steps 1 and 2 were the ones it would have been tempting to skip in the interest of
shipping the CLI sooner. A lock file whose hashes are defined by whatever the Python
implementation happened to do is not portable, and a drift signal that differs between
runtimes is worse than no drift signal — it teaches people to ignore it. Building them
first is what surfaced the numeric-tagging hazard above, before a lock file was in
anybody's repository.
