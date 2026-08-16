# Histos policies

Seven real policies, each in **YAML** and in **JSON**, ordered so that reading them
top to bottom is a tour of the format. The YAML carries the reasoning in comments;
the JSON is the same policy for machines — JSON has no comments, which is the whole
reason both spellings exist here.

If this is your first policy, start with the shorter
[policy-writing guide](../docs/writing-policies.md), then return here for complete
patterns at increasing complexity.

This directory is a **catalogue of the format**. It is not the same thing as its two
neighbours, and the difference is worth knowing:

| | what it is | who reads it |
|---|---|---|
| `policies/` | the format, shown at increasing complexity, in both spellings | a person deciding what to write, or an implementer deciding what to support |
| [`examples/`](../examples/) | runnable demo scripts and the one commented policy they use | somebody trying the library out |
| [`conformance/`](../conformance/) | language-neutral fixtures that define correct behaviour | a second implementation proving it agrees |

Everything here is checked by the reference engine's own test suite
([`tests/test_policies_gallery.py`](../tests/test_policies_gallery.py)): each policy
loads, validates, declares only features the engine implements, and hashes
identically to its JSON twin. A gallery that quietly stopped being true would be
worse than no gallery.

---

## The seven

| | protects | tools | introduces |
|---|---|---|---|
| [`01-minimal`](01-minimal.policy.yaml) | a single lookup | 1 | RBAC, argument schema, deny-by-default |
| [`02-tenant-isolation`](02-tenant-isolation.policy.yaml) | a multi-tenant document store | 2 | `resource.owns`, `bind`, role inheritance |
| [`03-rag-readonly`](03-rag-readonly.policy.yaml) | a retrieval agent | 2 | the return surface: projection, PII, canary, rate limits |
| [`04-refund-approval`](04-refund-approval.policy.yaml) | money | 2 | budget, human confirmation, strict returns |
| [`05-mcp-surface`](05-mcp-surface.policy.yaml) | a whole MCP server | 12 | granting **5 of 12**, and declaring the other 7 anyway |
| [`06-outbound-email`](06-outbound-email.policy.yaml) | an agent that can SEND | 4 | the egress pattern, undeclared-arg refusal, split tools |
| [`07-devops-deploy`](07-devops-deploy.policy.yaml) | irreversible infrastructure | 7 | enum as a wall, pinned versions, change freeze, asymmetric friction |

The first five are a tour of the format. The last two are a tour of **production
agent archetypes** - the communications agent, where the risk is data leaving, and
the infrastructure agent, where the risk is an irreversible action landing in the
wrong place. Between them they demonstrate the recipes in
[the reference's *From threat to policy* section](../docs/policy-reference.md#from-threat-to-policy).

Start with `01` even if it looks too small to matter. Four things are already true
there, and each is a decision the format made rather than a feature it happens to
have: a role calls only what it is granted; a tool absent from the file is denied;
an argument absent from the contract is denied; and a tool with no argument schema
is denied rather than waved through.

---

**Looking up what one line does?** [`docs/policy-reference.md`](../docs/policy-reference.md) is every key
in the format with its type, whether it is required, what it defaults to and what it actually changes. It
is generated from the schema, so it cannot drift from what the engine enforces. The tour below is for
learning the shape; the reference is for answering *"wait, what does `on_violation` do?"* at 2am.

## How a policy is put together

```yaml
schema_version: histos.policy/0.1   # which contract this document speaks
policy_id: refund-approval          # identity — excluded from the hash
version: "1"                        #   ,,       ,,
created_at: "2026-08-09T00:00:00Z"  #   ,,       ,,

requires:                           # a LOAD-TIME assertion, not policy content
  features: [rbac, budget, ...]     # refuse to load on an engine missing these

canaries: [CANARY-...]              # planted tokens, matched verbatim

tools:                              # a mapping keyed by name — a repeat is a
  make_refund:                      # duplicate key, which parsing already refuses
    access: write                   # read | write
    sensitivity: critical           # low | medium | high | critical
    budget: 20                      # total calls, per principal
    rate_limit: 60                  # calls per rolling window
    args: {...}                     # the argument contract — deny-by-default
    returns: {...}                  # the return contract
    bind: {tenant_id: principal.tenant_id}   # overwrite an arg from trusted identity
    resource: {owns: tenant_id, where: [...]}  # row-level authorization
    confirmation: {required: true, expires_in: 900}
    output: {project: true, strict: true, on_violation: redact_all}

roles:                              # grants are role-centric, never inline on the
  refund_officer:                   # tool: the reviewable question is "what can
    inherits: support_agent         # this role do", and inheritance needs a home
    allow: [make_refund]
```

### Two layers, kept apart on purpose

**Shape** — argument names and types — is *imported*: from JSON Schema, OpenAPI, an
MCP `tools/list` response, or a Python signature. Nobody should retype a twelve-tool
server.

**Authorization** — who may call it, on whose rows, how often, and what may come
back — is *authored*. No import can produce it, because it is not in the server's
metadata. JSON Schema can say *"invoice_id is a string"*; it cannot say *"support may
read only their own customer's invoice"*.

### The dangerous thing you cannot write here

The near-miss that Draft 0.1 removed from the language: comparing a
**caller-supplied** `tenant_id` argument to the principal's. That proves the caller
named their own tenant, not that the record is theirs — so for
`read_document(document_id, tenant_id)` an attacker passes someone else's
`document_id` with their own `tenant_id`, every check passes, and the tool keys on
`document_id`. Cross-tenant read.

`resource.owns` resolves the **accessed** record and compares its real owner. That
requires a `resource_resolver` on the host, and a resolver that echoes an argument
re-creates the hole — [`SECURITY.md`](../SECURITY.md) is explicit about it. A format
where the mistake is *unexpressible* beats one that warns about it, which is why the
warning, the strict-mode refusal and the flag behind it were all deleted along with
the construct.

---

## Your editor already knows this format

Every policy here starts with:

```yaml
# yaml-language-server: $schema=https://usehistos.dev/spec/policy-0.1.schema.json
```

That one line gives VS Code, JetBrains and anything else speaking the YAML language
server **completion, hover documentation and inline validation while you type** —
`sensitivit` underlined before you save, `enum` offering `low | medium | high |
critical`, an unknown key flagged where you wrote it rather than at load time. Copy
the line into your own `security.policy.yaml`; it is a comment, so it changes nothing
about the policy, including its `content_hash`.

**JSON policies cannot carry the equivalent.** Root keys are closed
(`additionalProperties: false`), so a `"$schema"` key is refused at load — the same
compatibility gate that refuses a policy written for a newer engine. Editors match
JSON policies by filename pattern instead (`*.policy.json`). Whether the format
should reserve `$schema` is [an open question, deliberately not settled in Draft
0.1](../docs/policy-format-draft-0.1.md).

The hosted schema is the convenient default. For an offline checkout, point the
directive at the local copy instead:

```yaml
# yaml-language-server: $schema=./spec/policy-0.1.schema.json
```

## Running them

```bash
histos validate policies/04-refund-approval.policy.yaml   # structural — the CI gate
histos review   policies/04-refund-approval.policy.yaml   # ready / review / blocked
histos coverage policies/05-mcp-surface.policy.yaml --tools search_tickets,get_ticket
histos explain  policies/04-refund-approval.policy.yaml make_refund \
    --role refund_officer --attr tenant_id=acme \
    --args '{"order_id":"ORD-1","amount":90000,"currency":"EUR","tenant_id":"evilcorp"}'
```

`explain` answers two audiences at once, and the split is deliberate:

```
developer:
  DENY [arg_schema] field=amount — amount: 90000 > maximum 50000
  remedy: fix the argument to match the tool's schema (type / range / length / pattern)
agent:
  ACTION_NOT_AUTHORIZED
```

The developer gets the field, the bound and the fix. The agent gets a code that
teaches it nothing about how to succeed on the next attempt. A denial that explains
itself to a manipulated model is a hint.

Two more worth trying, because they show fail-closed rather than a happy path:

- `--role support_agent` on `make_refund` → `DENY [rbac]`. The role inherits reads,
  not writes.
- a valid call on `make_refund` with no resolver wired →
  `DENY [no_resource_resolver]`. Declaring `resource` and forgetting the resolver
  does **not** silently skip the check.

### What `review` says about the gallery

Honestly, including the part that looks like a problem:

```
01-minimal            ✓ 1 ready    ⚠ 0    ✕ 0
02-tenant-isolation   ✓ 2 ready    ⚠ 0    ✕ 0
03-rag-readonly       ✓ 2 ready    ⚠ 0    ✕ 0
04-refund-approval    ✓ 2 ready    ⚠ 0    ✕ 0
05-mcp-surface        ✓ 5 ready    ⚠ 7    ✕ 0     ← "no role can call it"
06-outbound-email     ✓ 2 ready    ⚠ 2    ✕ 0     ← "no resource constraint"
07-devops-deploy      ✓ 6 ready    ⚠ 1    ✕ 0     ← "no role can call it"
```

The warnings are correct and the policies are still right - and each kind teaches a
different lesson about what an advisory tool can and cannot know.

The seven on `05` (and one on `07`): tools **declared and granted to nobody**, on
purpose. A tool declared with no grant denies with `rbac` ("your role has no grant").
A tool absent from the file denies with `unknown_tool` ("nothing governs this").
**Both refuse the call.** Only one of them tells a reviewer that a human looked at
`run_admin_query` and said no - which is the difference between a policy and a gap.

The two on `06`: **writes with no resource constraint**. The flag is right in
general - a write without row-level authorization is the IDOR shape - but sending
mail has no record to own; the bound is the recipient pattern, the budget and the
secret screening. The file says so in a comment at the exact spot a reviewer will
look. That is the intended workflow: `review` raises the question, a human answers
it *in the policy*, and the next reviewer reads the answer instead of re-deriving it.

`review` cannot tell "considered and declined" from "forgot", so it flags both, and
that is the right behaviour for an advisory tool.

---

## YAML and JSON are one policy, and that is a testable claim

The same document in both spellings hashes to one value. This is not a convenience —
it is what policy pinning, approvals bound to a policy hash, and *"the same policy is
deployed in both services"* actually rest on. Two engines can agree on every verdict
and still hash a policy differently, at which point approvals silently stop matching
across services and nothing looks broken.

```python
from histos import load_policy, load_bundle_json

yaml_hash = load_policy("policies/04-refund-approval.policy.yaml").content_hash()
json_hash = load_bundle_json(open("policies/04-refund-approval.policy.json").read()).content_hash()
assert yaml_hash == json_hash
```

| policy | `content_hash` |
|---|---|
| `01-minimal` | `sha256:372435e783e72ece…` |
| `02-tenant-isolation` | `sha256:a17438ca9d55f691…` |
| `03-rag-readonly` | `sha256:304016ac97d64d9d…` |
| `04-refund-approval` | `sha256:5dcc22c636dcdb7d…` |
| `05-mcp-surface` | `sha256:9a4160edf7d7f03d…` |
| `06-outbound-email` | `sha256:6aea36d469f62959…` |
| `07-devops-deploy` | `sha256:5fe57c6fe9065341…` |

The twins are emitted with their **keys in reversed order** so the match is a
demonstration and not a tautology, and `01-minimal.policy.json` additionally spells
out several defaults its YAML omits — `required: true`, `deny_secret_args: true`, the
whole `output` block. Same hash. Four rules make that hold, and they are format rules,
not implementation details:

- the hash is over the **canonical semantic model**, not the file bytes;
- **key order is irrelevant**;
- **metadata is excluded** — `policy_id`, `version`, `created_at` do not change it;
- **defaults normalize away** — stating a default means exactly what omitting it means.
  An engine that hashed them differently would invalidate every approval the moment
  somebody made a default explicit.

`requires` is also excluded: it is a load-time compatibility assertion, and if it
passed, it changed no decision. The JSON twins carry it anyway so they are faithful
copies rather than subsets.

---

## What this format deliberately cannot do

Named so nobody designs around their absence, and each for the same reason — a
security artifact that needs a precedence rule is a security artifact nobody reviews
correctly:

- **no expressions.** Comparisons only, against a literal or a trusted principal
  attribute. `bind` accepts exactly `principal.<attr>` and nothing else.
- **no deny rules.** Allow-lists only. Allow *and* deny needs precedence, and
  precedence in authorization is where the CVEs live.
- **no multiple inheritance.** One parent per role.
- **no nested object schemas.** Arguments are shallow-checked — a `type: object`
  argument is checked for being an object, not for its contents. Validate inside the
  tool, or keep arguments flat.
- **no per-environment overlays.** That is policy *lifecycle*, which is the control
  plane's job — see [`open-core-boundary.md`](../docs/open-core-boundary.md).
- **no semantic judgement.** "Is this action sensible", meaning-level injection
  detection, paraphrased exfiltration: permanently a different tier, reached through
  the `escalate` seam, which collapses to DENY when nothing is wired to it.

---

## Stability

`schema_version: histos.policy/0.1` is a **draft**. It is adopted and implemented —
the engine enforces exactly this and the [conformance corpus](../conformance/) pins
the behaviour — but inheritance, precedence and resource references are the parts
most likely to move before a 1.0 that promises stability. The reasoning behind each
decision is in [`docs/policy-format-draft-0.1.md`](../docs/policy-format-draft-0.1.md);
the machine-readable contract is [`spec/policy-0.1.schema.json`](../spec/policy-0.1.schema.json)
plus [`spec/decision-codes.json`](../spec/decision-codes.json).

An engine that only *partly* understands a policy refuses to load it. Both gates that
enforce that are deliberate and independent: an unknown key catches a policy written
for a newer engine (or a typo), and `requires.features` catches the subtler case where
a key is recognised but its semantics are not the ones the author meant.
