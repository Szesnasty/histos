# Design

What Histos is, what it decides, and on what its guarantee rests. For where
the guarantee *stops*, read [`../SECURITY.md`](../SECURITY.md) — the two documents
are meant to be read together, and the second one is the more useful of the pair.

## The problem

Protecting a tool-calling agent usually means standing up a proxy: models,
containers, network. That is the right shape for probabilistic content scanning —
prompt-injection detection, semantic risk. It is heavy for the most common need:
*enforcing deterministic policy at the tool boundary* — who may call which tool,
with which arguments, on which resource, how often, and what may come back.

## The claim

> **Hijacked. Still bounded.**

Not "harmless", and the difference matters. Histos does not detect prompt
injection and does not try to. The model can be convinced to attempt anything; the
gate ensures the attempt stays inside an envelope the model does not control.

An action that is *inside* policy still executes — €400 to the right tenant through
an allowed tool with valid arguments is a legitimate call whatever motivated it.
That residual has a name, **in-policy abuse**, and two shapes with different
answers: volume (`budget`, `rate_limit`, `limit_scope`) and ordering
(`call_sequence_constraint`). Both are visible only across calls, not within one.

## Trust model

- **Trusted:** the developer wiring the gates, and the `Principal` — role plus
  attributes — that the host binds **out of band**.
- **Untrusted:** external users, everything the agent reads, and **the tool name and
  arguments of every call**, which a manipulated model constructs.
- **Out of scope, named rather than hidden:** a malicious developer; a compromised
  dependency in the same process.

Identity is the load-bearing assumption and the library cannot enforce it. The host
sets `Principal` from workload identity or an authenticated session — never from a
tool argument or model output. This is exactly the piece MCP's enterprise-managed
authorization now standardises: it establishes *who* the caller is; Histos
decides *what they may do*.

## The core invariant

A decision may read only:

```
tool name  ·  arguments  ·  trusted principal  ·  static policy
```

Never conversation history, retrieved documents, or prior tool outputs. Everything
that can be influenced by an attacker is an *input to be judged*, never a *source of
the rule*. An attacker may make a check fail; they can never change what it
requires.

Resource attributes are the one thing fetched at decision time, and they come from a
**trusted, host-provided resolver** reading the real datastore — not from anything
the model said.

## Three mechanisms, three jobs

The most common design error in this space is one mechanism doing two jobs badly.
Draft 0.1 separates them and refuses to let them overlap:

| | question |
|---|---|
| **argument schema** | is this argument value admissible at all? |
| **`bind`** | what must the model not be allowed to choose? |
| **`resource`** | may this principal act on this *actual* resource? |

`bind` is the one worth dwelling on. Instead of *checking* that a caller-supplied
`tenant_id` matches the principal, the gate **overwrites** it with the trusted value
before any check runs. The wrong value becomes un-passable rather than merely
detected. This is why Draft 0.1 could delete the argument-comparison constraint
entirely: everything it did was either the argument schema's job or a confused
deputy waiting to happen.

## The decision chain

**PRE** — fail-fast, in order:

```
1  unknown_tool           no contract → refused (complete mediation)
2  rbac                   role allow-list, with inheritance
3  arg_schema             types, ranges, lengths, patterns, enums, array elements
4  resource_constraint    row-level authz against the RESOLVED resource
5  canary_exfil           a planted token in an argument (verbatim + normalized)
6  secret_detected        a checksum-verified credential in an argument
7  content_rule           OPTIONAL, opt-in, off by default — heuristic, not core
8  rate_limit / budget    consumed atomically at the point of execution
9  requires_confirmation  a trusted out-of-band approval, which the agent cannot mint
```

**POST** — what may reach the model:

```
1  output schema          strict returns: deny or redact a non-conforming result
2  projection             drop every field not declared in `returns`
3  canary                 redact planted tokens anywhere in the structure
4  sensitive fields       redact by name, recursively, honouring can_view
5  secrets                redact recognised credentials the backend leaked
```

Projection matters more than it looks: name-based redaction cannot protect a secret
that lands in an **undeclared** field, so deny-by-default is extended to the return
surface too.

## Fail-closed, everywhere

Any exception inside a check becomes DENY. No principal → DENY. A gated tool with no
argument schema → DENY. A policy this engine only partly understands → refused at
load. There is no fail-open mode and no "log and continue".

The consequence is accepted deliberately: a policy bug becomes an *availability*
incident. That is why evaluation is small, pure, dependency-free and microsecond-
scale — the evaluator has to be simple enough to reason about. "Availability over
safety" is expressible as an explicit policy rule, never as a fail toggle.

## Two audiences

A denial is two messages. `rule=resource_constraint field=amount expected=<=500
received=10000` is gold for a developer and a tuning hint for a hijacked agent. So:

- **developer / audit** — the full `GateDecision`: rule, field, expected, received,
  remedy, policy hash.
- **agent** — `ACTION_NOT_AUTHORIZED` / `CONFIRMATION_REQUIRED` and nothing tunable.

Adapters return the agent-facing form by default. Honest residual: the *fact* of a
denial is itself signal, and that is unavoidable; the guarantee is only that the
specific value or set that would let an agent walk the boundary is never handed over.

## Observe before enforce

`mode="observe"` evaluates and audits exactly as it would enforce, but blocks
nothing and modifies nothing. Records are unmistakable —
`effect=deny enforced=false executed=true` — so watching is never mistaken for
protecting. The intended path is *import → review → fix warnings → observe → read
the denied-but-executed decisions → enforce*.

## Audit

Every decision, including every denial. Arguments are never stored raw: each record
carries a keyed HMAC digest plus the argument *names*, alongside the `policy_hash`,
`policy_version` and `gate_version` that produced it. `JSONLAuditSink(hash_chain=True)`
gives an append-only, tamper-evident trace; pass a key for tamper-evidence against a
motivated writer rather than only against accident.

You cannot reconstruct a call from the trace. What you can do is *verify a decision*
— which is the useful thing.

## Complete mediation is the host's job

The gate can only mediate a tool it was handed. `Gate.coverage()` surfaces tools the
policy declares but that were never wrapped, and `histos coverage` fails CI on
tools exposed to the agent but absent from the policy. A tool that is neither
declared nor wrapped is invisible. Making every reachable tool flow through the gate
is the host's or the adapter's responsibility — which is why the framework adapter,
and above all the MCP server boundary, matter as much as the checks do.

## What is deliberately not here

Semantic judgement stays out of this layer, permanently: meaning-level injection
detection, paraphrased or re-encoded exfiltration, free-text PII with no structure,
"is this action sensible". Those are probabilistic and belong to a different tier,
reached through the `escalate` seam — which **collapses to DENY when nothing is
wired to it**, so the deterministic core is never weakened in order to add
semantics.

## Further reading

- [`../SECURITY.md`](../SECURITY.md) — the guarantee's limits, stated plainly
- [`policy-format-draft-0.1.md`](policy-format-draft-0.1.md) — the portable artifact
- [`../spec/`](../spec/) — schema and decision vocabulary
- [`../conformance/`](../conformance/) — what "the same policy behaves the same way" means
- [`open-core-boundary.md`](open-core-boundary.md) — what is open, and permanently so
