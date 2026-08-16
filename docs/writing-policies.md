# Writing policies

A Histos policy answers one reviewable question: **what may this authenticated
principal let an agent do, with which arguments, to which records, and what may come
back?** It is an allow-list. Anything the document does not authorize is denied.

This guide takes one tool from a Python function to a checked policy file. Use the
[policy gallery](../policies/README.md) for larger patterns and the generated
[policy reference](policy-reference.md) when you need the exact type or default of a
key.

## 1. Start with the tool shape

For one small tool, write the shape directly:

```yaml
# yaml-language-server: $schema=https://usehistos.dev/spec/policy-0.1.schema.json
schema_version: histos.policy/0.1
policy_id: support-search
version: "1"

tools:
  search_docs:
    access: read
    args:
      query: {type: string, min_length: 1, max_length: 500}
    returns:
      title: {type: string}
      snippet: {type: string}
    output:
      project: true
      strict: true

roles:
  support:
    allow: [search_docs]
```

Save it as `security.policy.yaml`. The first comment gives compatible editors
completion and inline validation from the same schema the engine implements.

This small document already has useful boundaries:

- only the `support` role may call `search_docs`;
- an unknown tool or argument is denied instead of ignored;
- `query` must be a non-empty string no longer than 500 characters;
- only the declared return fields may re-enter the model;
- a return with the wrong shape is replaced according to the strict-output policy.

For a real tool surface, do not maintain its JSON Schema twice. Import MCP, OpenAI or
OpenAPI definitions and then author the security semantics:

```bash
histos import tools.json --kind mcp --out security.policy.yaml
```

The command also writes `security.policy.lock.json`, which lets `histos drift` detect
later schema or description changes. See [tool contracts and drift](tool-contracts.md)
for the update workflow and its limits.

## 2. Author what a schema cannot know

An imported schema can say that `invoice_id` is a string. It cannot decide who may
use the tool, whether the invoice must belong to the caller, whether a payment needs
approval, or which fields may return to the model. Those decisions belong in the
policy.

### Grant the smallest role

```yaml
roles:
  viewer:
    allow: [get_invoice]
  billing:
    inherits: viewer
    allow: [pay_invoice]
```

Grants are allow-lists. Histos has no deny rules or precedence rules. A tool present
under `tools` but granted to no role is still denied and records that a human reviewed
the surface.

### Bind trusted values instead of checking self-declaration

```yaml
tools:
  pay_invoice:
    args:
      invoice_id: {type: string}
      tenant_id: {type: string}
    bind:
      tenant_id: principal.tenant_id
```

`bind` overwrites the model-supplied value from a trusted `Principal` before the
argument checks. Build that principal from a verified session or workload identity,
never from the conversation. The full host-side rules are in [Identity](identity.md).

### Authorize the accessed record

```yaml
tools:
  pay_invoice:
    resource:
      owns: tenant_id
      where:
        - {field: status, op: eq, value: approved}
```

This requires a host `resource_resolver` that fetches the real invoice. A resolver
that echoes `args["tenant_id"]` proves only what the caller claimed and recreates the
cross-tenant hole the rule is meant to close.

### Put friction and output controls on dangerous tools

```yaml
tools:
  pay_invoice:
    access: write
    sensitivity: critical
    budget: 10
    confirmation: {required: true, expires_in: 900}
    returns:
      status: {type: string, enum: [paid, pending]}
      reference: {type: string}
    output:
      project: true
      strict: true
      on_violation: redact_all
```

Confirmation is out-of-band and bound to the exact action. With no trusted callback,
the call does not proceed. Limits and the built-in approval store are process-local;
read [SECURITY.md](../SECURITY.md) before treating them as distributed controls.

## 3. Check the policy before wiring it

Use all four checks; they answer different questions:

```bash
histos validate security.policy.yaml
histos review security.policy.yaml
histos coverage security.policy.yaml --tools search_docs,get_invoice,pay_invoice
histos explain security.policy.yaml pay_invoice \
  --role billing --identity user-42 --attr tenant_id=acme \
  --args '{"invoice_id":"INV-9","tenant_id":"attacker-choice"}'
```

- `validate` checks the format and refuses unknown or unsupported features.
- `review` finds risky but valid choices that need a human decision.
- `coverage` compares the policy with the tools the agent can actually see.
- `explain` evaluates one request without executing the tool.

Treat `review` as a question, not an oracle. Some writes genuinely have no resource
to own; document why the recipient pattern or another bound is sufficient. Do not
silence a warning by adding a fake resolver.

## 4. Enforce the same artifact

```python
from histos import Principal, protect, use_principal

def search_docs(query: str):
    return {"title": "Refunds", "snippet": "Refunds require a receipt."}

guarded = protect([search_docs], policy="security.policy.yaml")

principal = Principal(role="support", identity="user-42")
with use_principal(principal):
    result = guarded.tools["search_docs"](query="refund policy")
```

Give the agent `guarded.tools`, not the original functions. `protect()` wraps every
supplied callable; one missing from the policy or from every grant remains wrapped
and denies by default. Keep the original callable out of every alternate registry or
execution path.

For an existing application, start with `mode="observe"`, inspect the audit records,
close coverage and review findings, then switch to the default `enforce` mode. Observe
mode measures what would be denied; it does not provide a security boundary.

## 5. Keep policy and tools from drifting

When the source definition changes:

```bash
histos drift security.policy.yaml --source tools.json --kind mcp
histos import tools.json --kind mcp --update security.policy.yaml
```

Review the diff. The update refreshes imported argument and return shapes while
preserving authored roles, ownership, bindings, confirmation and output rules. YAML
comments make `--update` stop rather than discard reasoning; `--force` is an explicit
choice to accept that loss.

## Before enforcement

- Every tool exposed to the agent appears in `coverage`.
- Every role grant is intentional; no role or attribute comes from model-controlled
  data.
- Every tenant-sensitive read or write resolves the real resource.
- Arguments have useful types and bounds; undeclared arguments remain refused.
- Dangerous writes have the required limits or out-of-band confirmation.
- Return fields are declared, projected and marked `sensitive` where needed.
- The agent receives only wrapped callables, and the backend still authorizes the
  operation independently.
- `validate`, `review`, `coverage`, `explain` and the drift check run in CI.

Next: read the gallery in order from
[`01-minimal`](../policies/01-minimal.policy.yaml) through
[`07-devops-deploy`](../policies/07-devops-deploy.policy.yaml).
