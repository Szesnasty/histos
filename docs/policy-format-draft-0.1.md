# Histos Policy Format — Draft 0.1

**Status: adopted and implemented.** The reference engine enforces exactly this, and
the [conformance corpus](../conformance/) runs in its own test suite. Still a
**draft**: see *Deliberately not in Draft 0.1* for what is unsettled, and expect
breaking changes before a 1.0 that promises stability.

Artifacts: [`spec/policy-0.1.schema.json`](../spec/policy-0.1.schema.json) ·
[`spec/decision-codes.json`](../spec/decision-codes.json) ·
[`examples/security.policy.yaml`](../examples/security.policy.yaml) (a commented policy)

This document records **why** the format has the shape it has. Each decision below
was a real fork, and the reasoning matters more than the syntax — a format is much
harder to change than an API, so the arguments are kept rather than summarised.

---

## Why a format, and not just a library config file

If the same policy is to hold wherever an agent acts, the artifact — not any one
engine — is the product:

```
                security.policy.yaml
                        │
              Histos Policy Format
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
     Python SDK     TS/JS SDK     MCP adapter
```

There must never be a `policy-python.yaml` and a `policy-mcp.yaml`. That single
constraint is what turns this from a library into a contract — and it is also what
makes format cleanliness outrank Python API convenience from here on.

**The contract is three documents, not one.** People remember the first and are bitten
by the other two:

| | answers |
|---|---|
| the schema | will the policy load |
| the decision codes | will two engines name the same refusal the same way |
| the canonicalization rules | will two engines compute the same `content_hash` |

Skip the second and your MCP adapter denies for a different reason than Python and
nobody notices, because the agent-facing message is identical by design. Skip the
third and approvals bound to a policy hash stop matching across services — the
failure nobody predicts, because it will not be in `arg_range`, it will be in how
one language serialises `1.0`.

## Version numbering

`schema_version: "histos.policy/0.1"`. The current `/1` was **never released**,
so the version space can be reused downward exactly once — now. That is a real
argument for settling this before the first publish rather than after.

The namespace prefix (`histos.`) and the schema `$id` host
(`https://histos.dev/spec/policy-0.1.schema.json`) are both settled. They were the
last reason to delay publishing this draft, and the reason the name had to be locked
first: the prefix is part of every policy file, and the `$id` is part of every
`$ref`. Neither moves again.

---

## The decisions

All adopted. Kept in full because the reasoning is the durable part. The first six were
settled together; the seventh (`escalate`) landed after them, under the same rules.

### 1. `tools` is a mapping keyed by name

```yaml
# now                          # Draft 0.1
tools:                         tools:
  - name: make_refund            make_refund:
    access: write                  access: write
```

The engine currently carries a hand-written `duplicate tool name` check **only
because `tools` is a list**. As a mapping, a repeated name is a duplicate key, which
canonical parsing already refuses. Code written to repair the consequence of a shape
is evidence about the shape.

### 2. Argument bounds use JSON Schema vocabulary

`maximum` / `minimum` / `exclusive_*`, not `max` / `min`. The importers bridge JSON
Schema, OpenAPI and MCP, all of which use these words. A four-character saving buys a
dialect that every import then has to translate.

### 3. Grants are role-centric

Inline `allow: {roles: [support]}` on the tool reads better in a small file, but:

- the reviewable question is *"what can the support role do"*, not *"who can call
  make_refund"*, and over-provisioning lint needs the role-centric view;
- role inheritance has nowhere to live in the inline form.

**Do not support both.** Two ways to express one grant in a security artifact is a
precedence question, and precedence questions are exactly the compatibility prison.

### 4. `bind` is a mapping with a `principal.` reference

```yaml
# now                                    # Draft 0.1
bindings:                                bind:
  - field: tenant_id                       tenant_id: principal.tenant_id
    principal_attr: tenant_id
```

Reads as what it does. **Hard constraint:** the value is validated as exactly
`principal.<attr>` and nothing else. The moment an expression is allowed there, the
format has an expression language and stops being deterministic by construction.

### 5. `resource.owns` is first-class; `source: call` is gone

```yaml
# now                                          # Draft 0.1
constraints:                                   resource:
  - field: tenant_id                             owns: tenant_id
    op: eq                                       where:
    source: resource                               - {field: status, op: ne, value: cancelled}
    principal_attr: tenant_id
```

Making the safe case the *short* case, and leaving the general form for genuine
conditions on resolved resource state, is the whole idea.

The removal of `source: "call"` is the substantive part. Every use of it is either:

- **redundant** — `{field: amount, op: le, value: 1000}` is `amount: {maximum: 1000}`
  written worse: it bypasses type validation and does not appear in the tool's
  contract, where a reader looks for it; or
- **the IDOR footgun** — `source: call` + `principal_attr` proves the caller named
  their own tenant, not that the resource is theirs. It is already flagged by
  `review_policy`, refused by `Policy.validate` under strict, and documented as DANGER.

A format where the dangerous construct is *unexpressible* beats one where it is
merely warned about. This is the same move as making the arg schema deny-by-default.

**Cost, paid:** this was the only decision with real migration work. The Python
`Constraint` API lost `source=` too — keeping it in code while removing it from the
artifact would mean something expressible in Python could not round-trip to a policy,
breaking portability at exactly the seam this format exists to protect. Three
mitigations became dead code and were deleted with it: the `review_policy` warning,
the `Policy.validate` strict refusal, and `contracts.self_declared_authz`.

### 6. Output settings group under `output`

Five flat keys (`project_output`, `strict_returns`, `on_output_violation`,
`scan_output_for_canary`, `redact_secret_output`) become:

```yaml
output:
  project: true
  strict: false
  on_violation: redact_all
  scan_canary: true
  redact_secrets: true
```

Now-or-never: with unknown keys refused, regrouping later is a breaking change.
Same reasoning makes `confirmation` an object rather than a boolean — approver rules
(separation of duties, N-of-M, expiry) will need fields, and widening a boolean later
breaks every policy in the field.

### 7. `escalate` is a seam, and its default is DENY

```yaml
tools:
  wire_transfer:
    escalate: {required: true}
```

The format is deterministic and stays that way. `escalate` is the one key that hands a
call to something that is not — a host-wired semantic tier — and the whole design is in
what it is *unable* to express.

**It cannot name a tier, a model, an endpoint or a threshold.** Those are deployment,
and a policy that named them would stop being portable the moment it left the service
that wrote it. The key says *this call needs meaning-level judgement*; which judge, and
on what, is the host's.

**It cannot be spelled as an allow.** The tier is consulted after every deterministic
check has passed, so the only thing it can do is *release* a call the rest of the chain
already permitted. There is no verdict, and no policy syntax, that lets a probabilistic
layer permit what a deterministic one refused. A format in which that is unexpressible
beats one where it is discouraged — the same argument as `source: call` in decision 5.

**And absence is a denial, not a skip.** An engine with no tier wired answers
`no_escalation_tier` and refuses. This is the load-bearing rule and it belongs to the
format rather than to an engine: the alternative — treat "no tier" as "nothing to
check" — would make the same policy mean strictly less on every deployment that had not
finished wiring one, which is precisely the silent-partial-enforcement failure the
unknown-key gate exists to prevent. It is pinned by
[`conformance/decisions/escalate-without-a-tier-denies.json`](../conformance/decisions/escalate-without-a-tier-denies.json),
so a port cannot pass the corpus without reproducing it.

An object rather than a boolean, for the reason decision 6 gives about `confirmation`:
which tier and what it is asked are fields this block will grow, and widening a boolean
afterwards breaks every policy in the field.

**This revises a commitment, so it is spelled out rather than slipped in.**
[`open-core-boundary.md`](open-core-boundary.md) promised the semantic tier would be
reached through an *engine-level* seam and "not through a policy key". That promise was
protecting something real — a format must never carry a key whose purpose is to call a
paid product — and that part is kept intact: `escalate` names no tier, no vendor, no
endpoint and no subscription, and a host satisfies it with a local model, a regex, a
second human, or a flat refusal. What a runtime-only seam could not do was be
*reviewed*. Which calls need meaning-level judgement is a security decision; leaving it
in wiring code put it outside the artifact a reviewer reads, outside the diff, and
outside the hash an approval binds to. A routing rule a policy review cannot see is not
a smaller commitment than a key — it is the same commitment, unenforced.

**Cost, paid:** a new key in the hashed model moves every `content_hash`. Emitting it
only when set would have kept them stable, at the price of a conditional rule in the one
artifact two implementations must reproduce byte for byte — and a hash rule nobody can
restate in a sentence is how approvals stop matching across services without anyone
noticing. The regular rule wins; the hashes move once, before 1.0.

---

## Deliberately *not* in Draft 0.1

Named so nobody assumes they are coming, or designs around their absence:

- **Expressions or a condition language.** Comparisons only, against a literal or a
  trusted principal attribute.
- **Cross-field rules** (`mode: wire` ⇒ `iban` required). Wanted, but it needs a
  shape that does not become an expression language; not settled.
- **Multiple inheritance** for roles. Single parent, because precedence between two
  parents is a rule nobody will remember correctly at review time.
- **Deny rules.** Allow-lists only. A format with both allow and deny needs precedence,
  and precedence in authorization is where the CVEs live.
- **Nested object schemas.** Arguments are shallow-checked; `SECURITY.md` says so.
- **Per-environment overlays.** That is policy *lifecycle*, and lifecycle is the
  control plane's job — see [`open-core-boundary.md`](open-core-boundary.md).
- **The identity mapping.** `finance-refund-operator → refund_officer` is real, and
  every deployment needs it, but it belongs in the host — see
  [`identity.md`](identity.md). A directory GUID in the `roles` block would tie a
  policy to one IdP in one tenant and make it unreviewable, which is the opposite of
  a portable artifact.

  Whether the mapping should eventually be *its own* small artifact — versioned,
  diffable, reviewable, and separate from the policy — is a genuine open question,
  and the honest answer today is that nobody has deployed this against two identity
  providers yet. Naming it here so nobody designs around its absence: if it lands, it
  lands in 0.2, pulled by a real deployment rather than by symmetry.
- **A `$schema` key.** Root keys are closed (`additionalProperties: false`), so a
  JSON policy cannot point an editor at its own schema the way a YAML one can with a
  `# yaml-language-server:` comment. Editors match JSON policies by filename instead.
  Reserving `$schema` is a small, tempting change with a real question attached —
  whether it joins `policy_id` and `version` in the metadata excluded from the
  content hash — so it waits rather than being slipped in.

## Conformance corpus

Two properties, without which the corpus rots into documentation of what the engine
used to do:

**1. The reference engine runs the fixtures as part of its own test suite.** If a
change to Python breaks the contract, the reference engine's own suite fails that day
— not the TypeScript port, eighteen months later. *(That suite is not yet automated:
[known debt D2](tech-debt.md).)*

**2. The corpus covers canonicalization, not only decisions.** Alongside
`(policy, principal, call) → expected decision` fixtures there must be
`same policy, two spellings → identical content_hash` fixtures. That is where two
implementations actually diverge.

```
conformance/
  decisions/      rbac/ arg-schema/ resource-authz/ trusted-binding/
                  limits/ confirmation/ output-projection/ canary/
  canonicalization/   yaml-vs-json/ number-forms/ key-order/ duplicate-keys/
  compatibility/      unknown-key/ unknown-feature/ unsupported-version/
```

## Implementation status

All seven are implemented in the reference engine, and the behaviour is pinned by the
[conformance corpus](../conformance/) rather than by these paragraphs. Notably:

- `content_hash` is computed over the **canonical semantic model**, not the file:
  YAML and JSON of the same policy hash identically, key order is irrelevant,
  metadata (`policy_id`, `version`, `created_at`) is excluded, and **defaults are
  normalized away** — stating a default means the same as omitting it. That last one
  is a format rule, not an implementation detail: an engine that hashed them
  differently would invalidate approvals whenever somebody made a default explicit.
- `requires` does **not** affect the hash. It is a load-time compatibility assertion,
  not policy content; if it passed, it changed no decision.
- Compatibility is two independent gates, because they fail differently: an unknown
  key catches a policy written for a newer engine (or a typo), while
  `requires.features` catches the subtler case where a key is *recognised* but its
  semantics are not the ones the author meant.
