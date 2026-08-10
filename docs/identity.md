# Identity

> **The gate is exactly as strong as the `Principal` you bind to it.**

Every guarantee in [`SECURITY.md`](../SECURITY.md) rests on one sentence, and this
document is that sentence expanded: **identity comes from a trusted layer, policy is
static and developer-owned, and the model supplies only a request to act.**

Histos does not authenticate anybody. It has no notion of a user, a session, a token
or a directory, and it is not getting one. That is a boundary, not a gap — the
library's job starts *after* somebody else has established who is calling.

## The library cannot enforce this, and says so

There is no check that could distinguish a `Principal` built from a verified access
token from one built out of a string the model produced. Both are the same object by
the time the gate sees them. So this is stated as a **condition**, in the trust model,
in `SECURITY.md`, and here — rather than implied by an API that looks safe.

If you take one thing from this file: an injected instruction cannot remove a gate
compiled into your code, but it does not have to, if it can influence the identity the
gate compares against.

## Where the line runs

```
  user or service
        │
        ▼
  your identity provider          ← authenticates. Entra ID, Okta, Auth0,
        │                            Keycloak, your own IAM, workload identity
        │  token / session
        ▼
  your host: API, agent runner, MCP gateway
        │
        ├── verify the token          ← signature, issuer, audience, expiry
        ├── read the claims
        └── map external roles → policy roles
        │
        ▼
  Principal(role=…, identity=…, attributes={…})
        │
        ▼
  use_principal(principal)            ← a context variable, set by the host
        │
        ▼
  the agent runs, and proposes tool calls
        │
        ▼
  Histos: may THIS principal call THIS tool,
          with THESE arguments, on THIS resource?
        │
        ▼
  your backend, which authorizes again in the user's context
```

Three different questions, three different answers, and none of them replaces
another:

| | asks | answered by |
|---|---|---|
| authentication | *who is this?* | your identity provider |
| **agent authorization** | *what may this identity let an agent do?* | **Histos** |
| resource authorization | *may this operation touch this data, right now?* | your backend |

The third is not optional. Histos is defense in depth: if a tool calls a downstream
system with an admin token, the gate becomes your only line of defence, which is a
bad place to be. Run downstream calls with least privilege and in the user's context
anyway.

## What Histos needs from you

```python
from histos import Principal, use_principal

principal = Principal(
    role="refund_officer",              # a policy role — see mapping, below
    identity=claims["oid"],             # for the audit trail
    attributes={"tenant_id": claims["tid"]},   # trusted values policy may compare
    can_view=frozenset({"pii"}),        # which sensitivity classes may reach this caller
)

with use_principal(principal):
    await agent.run(...)
```

- **`role`** decides grants. It is the only thing RBAC reads.
- **`attributes`** is the trusted half of every comparison: `bind: {tenant_id:
  principal.tenant_id}` and every `principal_attr` condition resolve from here, and
  **only** from here. A missing attribute is a DENY (`arg_binding_unresolved`), never
  an injected `None`.
- **`identity`** is not used for decisions. It is what makes an audit record answer
  *who*.
- **`can_view`** gates the sensitivity classes a caller may see in returns.

Note what is *not* reachable: `role` cannot be referenced from a policy at all.
`principal.role` in a `bind` would look for `attributes["role"]`, not the role field.
That is deliberate — grants are decided by the engine, not smuggled through an
argument.

## The mapping layer

Your identity provider speaks its own vocabulary. Policies must not.

```
  Entra app role                    Histos role
  finance-refund-operator     →     refund_officer
  support-tier2               →     support_agent

  Okta group                        Histos role
  eng-oncall                  →     incident_responder
```

Keep this table in your host, next to your auth code. **Do not put provider
identifiers in the policy**, however tempting:

```yaml
# NO — this policy now only works on one directory, in one tenant
roles:
  "a9481de2-f123-4c77-9e21-0d3b1f7a5c88":
    allow: [make_refund]

# YES — this policy is a portable artifact
roles:
  refund_officer:
    inherits: support_agent
    allow: [make_refund]
```

The whole claim of a portable policy format is that the same document holds in
Python today, in another runtime tomorrow, and behind a different IdP at a different
customer. A directory GUID in the `roles` block breaks all three at once. It also
makes the file unreviewable: a security lead can tell you whether `refund_officer`
should have `make_refund`; nobody can tell you that about `a9481de2`.

**Histos says "this principal has role `refund_officer`". It never says "this Azure
claim has this value".**

## The five ways to get this wrong

Each of these compiles, runs, and produces a policy that enforces nothing.

### 1. The role comes from a tool argument

```python
# NO
def run_tool(role: str, **kwargs):
    with use_principal(Principal(role=role)):
        ...
```

The model constructs tool arguments. This hands it the ability to choose its own
permissions, and every check downstream is then arithmetic on a number the attacker
picked.

### 2. The role comes from model output

```python
# NO
plan = llm.plan(user_message)
with use_principal(Principal(role=plan.suggested_role)):
```

Same failure, one step further from view. Anything derived from the conversation —
including a "classification" step run by a second model — is attacker-reachable.

### 3. The token is decoded but not verified

```python
# NO — decodes the payload, checks nothing
claims = jwt.decode(token, options={"verify_signature": False})
```

An unverified JWT is a user-supplied JSON document with a dot in it. Verify:
**signature** against the provider's JWKS, **`iss`**, **`aud`**, **`exp`/`nbf`** — and
pin the expected **algorithm** rather than trusting the token's own `alg` header.
Getting this wrong is the most common way the whole chain fails, and it fails
silently: everything works, for everybody, including the attacker.

### 4. The identity comes from a header the caller controls

```python
# NO
principal = Principal(role=request.headers["X-User-Role"])
```

Fine behind a gateway that *sets* that header and strips any inbound copy. Fatal if
the header can arrive from outside — and "our gateway strips it" is a claim worth
verifying rather than assuming.

### 5. `fixed_principal` on a multi-tenant server

```python
# NO, on a server
safe = gate(tool, policy=policy, fixed_principal=Principal(role="admin"))
```

`fixed_principal` binds **one identity for the lifetime of the wrapper**. It is named
to be hard to reach for by accident, and it is correct for a single-identity script,
a worker, or a cron job. On a server handling many callers it means every caller runs
as that identity. Use `use_principal()` per request.

### And the sixth, which is about resources rather than identity

A `resource_resolver` that echoes an argument instead of fetching the record:

```python
# NO — this proves the caller named their own tenant, not that the record is theirs
resolver = lambda tool, args: {"tenant_id": args["tenant_id"]}
```

Covered in full in [`SECURITY.md`](../SECURITY.md); repeated here because it is the
same mistake wearing different clothes — comparing attacker-supplied data against
itself.

## Claims worth reading, by provider

Names only, so you know what to look for. **Verify the token first** — the list below
is what to read *after* verification, never instead of it.

| provider | identity | tenant / org | roles or groups |
|---|---|---|---|
| Microsoft Entra ID | `oid` | `tid` | `roles` (app roles), or `groups` |
| Okta | `sub` | org is the issuer | `groups` |
| Auth0 | `sub` | `org_id` | a namespaced custom claim |
| Keycloak | `sub` | realm is the issuer | `realm_access.roles`, `resource_access.<client>.roles` |
| workload identity (SPIFFE) | the SPIFFE ID | encoded in the trust domain | — the workload *is* the role |

Prefer a **stable, immutable** identifier for `identity`: Entra's `oid` rather than
`upn` or `email`, which are mutable and reusable. An audit trail that points at a
recycled address is worse than one that points at an opaque id.

## Why there is no `histos-auth-entra`

It would be convenience wearing a security label. The failure modes above are not
"could not parse a JWT" — they are *forgot to verify it*, *read the role from
something the agent can reach*, *bound one identity for every caller*. A package that
turns claims into a `Principal` prevents none of them, and it would add a dependency
surface plus a per-provider maintenance burden to a library whose strongest single
sentence is that it has no runtime dependencies at all.

What is worth having instead is this document, a review checklist, and an API where
the dangerous option is the one with the long name.

If a provider integration ever ships, it will be because real deployments asked for
the same one twice — the same rule that governs everything else on
[`roadmap.md`](roadmap.md).

## Checklist

Before an agent handles anything that matters:

- [ ] Every token is verified: signature, `iss`, `aud`, `exp`, pinned algorithm.
- [ ] `Principal` is built **only** from verified claims or an authenticated session.
- [ ] Nothing in `Principal` derives from a tool argument, a model output, or a
      caller-supplied header.
- [ ] External roles are mapped to policy roles in your host, and no provider
      identifier appears in the policy file.
- [ ] `use_principal()` per request; `fixed_principal` only where there genuinely is
      one identity.
- [ ] Every `resource_resolver` reads the datastore, never the arguments.
- [ ] The backend still authorizes in the user's context. Histos is the second lock,
      not the only one.
- [ ] `identity` is a stable identifier, so the audit trail stays meaningful.
