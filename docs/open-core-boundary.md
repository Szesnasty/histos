# The open/closed boundary

This project is open-core. This document says exactly where the line runs, why it
runs there, and how to decide for a capability that does not exist yet. It is a
commitment, not a marketing page: if a future release contradicts it, that is a
bug in the release, not a clarification of the policy.

## The rule

> **Everything that *enforces* is open. What is sold is *operating* enforcement —
> across time, across services, and with people in the loop.**

The line is not drawn by how strong the protection is. It is drawn by the shape of
the problem being solved.

**Every deterministic check is Apache-2.0, permanently — including distributed
enforcement.** A shared limit backend, cross-process budgets, org-wide rate limits:
open. There is no paid tier that makes a single deployment *safer*. The free gate
is meant to be the best deterministic gate available, with nothing held back.

That is a commercial choice as much as an ethical one. A withheld check is forked
in an afternoon; a service is not. Drawing the line at capability would give away
the moat and keep the resentment.

## Where things fall

| Open (Apache-2.0, permanently) | Commercial |
|---|---|
| The whole PRE chain — RBAC, argument schema, resource constraints, trusted argument binding, canary, secret detectors, egress allowlists, path containment, structural caps, cross-field rules, sequence constraints | — |
| The whole POST chain — output projection, strict returns, sensitive-field redaction, secret redaction, exception redaction | — |
| Limits, **including distributed** — shared limit backend, `limit_scope`, per-tenant budgets | — |
| The approval **primitive** — single-use, action-bound, policy-hash-bound, expiring | Approval **workflow** — who may approve what, separation of duties, N-of-M, delivery channels, escalation |
| Local audit — JSONL, hash chain, keyed HMAC, `audit verify` | Retention and evidence — durable central store, attestation, OTel/OCSF export, auditor packs |
| `coverage()` for one deployment, and the CI gate built on it | Fleet inventory — "every ungated tool across every service" |
| `init` → `observe` → `suggest`, locally, from your own log | Cross-service analytics — peer comparison, in-policy-abuse detection, org-wide rule proposals |
| The policy format, canonicalization, content hash, conformance suite | Policy lifecycle — authoring UI, diff, staged rollout, rollback, change history |
| Every framework adapter — LangChain, LangGraph, MCP client and server, OpenAI Agents — **and the ACS dispatcher adapter** | Fleet incident response — kill switch, break-glass grants, denial lockout, progressive enforcement |
| The decision record: policy hash, rule, principal, args digest, resource, redactions — everything needed to reproduce a verdict | **Change impact** — replay a proposed policy against recorded traffic: *"this diff would have admitted 184 calls the current policy refused"* |
| Deterministic re-evaluation of one recorded decision, locally | **Proof** — signed before/after over a corpus of real or synthetic attacks, retained, exportable: *"this exploit does not pass the contract now running"* |
| The CLI | The web UI |
| — | The semantic/probabilistic tier, reached through the `escalate` seam — which **collapses to DENY when it is absent**, so not paying never weakens the gate |

## Why this library can sell what the alternatives cannot

The two rows above — change impact and proof — are not dashboards bolted onto a
library. They are the only commercial capabilities that *follow from* how the engine
is built, and they are worth stating separately because they explain why the paid
tier is not arbitrary.

A verdict here is a function of a **canonical decision input** against a policy
identified by a content hash, with a conformance corpus fixing what that hash must
decide. Most of the chain — deny-by-default, RBAC, argument schema, resource
constraints, canary, secret detectors — is a pure function of
`(principal, tool, args, resolved resource, policy)`. Two steps are not, and naming
them is the difference between a reproducibility claim and a slogan: **rate/budget
limits** read counters over a rolling window, and **confirmation** consults a
single-use approval store. The canonical input therefore also carries the counters,
the approval state and the evaluation time those are measured against. `LimitStore`
already takes an injectable clock, which is what makes recording them enough.

Three consequences:

- the same inputs and the same hash produce the same verdict, on any machine, at any
  later date — so a decision can be **replayed**, not merely logged;
- a proposed policy can be evaluated against yesterday's traffic before it merges,
  because the recorded input carries the clock and the counters the original decision
  used, rather than consulting today's;
- "this attack cannot pass" is a **reproducible claim**, which is what an auditor,
  a customer security questionnaire, and an incident review all actually want.

No runtime we are aware of currently treats a reproducible decision as a
first-class contract; the ones whose verdicts consume a host-supplied snapshot or
accumulated session state would have further to travel to get there. The
discipline that makes the free library austere is
the same discipline that makes the paid product possible — which is the healthiest
relationship an open core can have with its commercial side.

**The corollary is a constraint, not a bonus.** Anything that makes a decision
irreproducible — hidden state, wall-clock dependence, a network call on the decision
path — damages the commercial product before it damages the library. Determinism is
now a revenue property, and regressions against it are treated accordingly.

## Deciding a capability that is not on the list

Three questions, in order:

**1. Would withholding it make a single deployment less safe?**
If yes → open, without further discussion. This is the load-bearing test, and it is
the one that survives contact with an actual roadmap argument.

**2. Does it need a database, a UI, or a human?**
If no → open, by default. A competent team builds it in a week anyway.

This is a *proxy* for the first question, and it misfires in one direction worth
naming: **analysis tooling**. Change impact and attack replay need no database and no
UI — they run against a local audit log — yet withholding them makes nobody less
safe, because neither one enforces anything. They tell you what a policy *would*
decide; the policy still decides it for free. When questions 1 and 2 disagree,
question 1 wins.

**3. If this were open, would the commercial product stop making sense?**
If yes → the problem is not this capability. The problem is that the commercial
product is too thin, and you just found out cheaply.

The last question matters most, because the temptation always arrives as *"this one
would make a good paid feature"* — which is a symptom of an underdeveloped control
plane, never of an over-generous library.

## Two commitments about the format itself

The boundary is only credible if it cannot leak into the artifact.

**No key exists in the policy format whose purpose is to call a paid product.** The
semantic tier is reached through an engine-level seam — `GateDecision.escalate`, a
runtime property — and not through a policy key that reads as an advertisement to
every open-source user. A format that ships hooks nobody can use without a
subscription is a format nobody should adopt as a standard.

**The format is one format.** There is no enterprise dialect, no commercial-only
`schema_version`, and no key the conformance corpus does not cover. A policy written
against the free runtime decides identically under a paid deployment, or the paid
deployment is wrong.

## The wall a user eventually hits

A boundary is honest when the first wall is a **change in the shape of the
problem**, never a degraded capability.

```
day 1      pip install, wrap the tools, run in observe   → free, complete
week 1     policy in git, coverage + validate in CI      → free
month 1    enforce in production, one service            → free, complete
           ← real protection, nothing paid. That is the point.

month 3    five services, three teams
           "which policy version is running where?"
           "who approved that refund on Tuesday?"
           "the auditor wants six months of denials"     → the wall
```

Nothing was taken away at month 3. The problem became a fleet problem, and a
library does not solve fleet problems. Nobody feels cheated that a Python package
has no dashboard and does not remember last quarter.

Compare the dishonest version — *"your budget is per-process unless you pay"*.
Same capability, artificially degraded, and the user can see it. That version is
rejected here.

## Architectural consequence: the API is never on the decision path

The commercial control plane integrates over the network. It must never sit
between an agent and its tool:

```
policy      pull and cache locally
decision    local, in-process, microseconds   ← never over the network
audit       pushed asynchronously
limits      periodically synchronised
approvals   the only thing that legitimately blocks (and is slow by nature)
```

A hosted gate answering per tool call would add latency to every call, turn a
cloud outage into either an availability incident or a security hole, and
reintroduce exactly the proxy that [`design.md`](design.md) exists to separate from.
The seams already exist for the correct shape: `AuditSink` is a runtime-checkable
Protocol, so a different sink substitutes without touching the engine. `LimitStore`
and `ApprovalStore` are still concrete classes and are heading the same way — worth
naming, because a seam that is only a plan is not yet a seam.

## Scope of the commercial side, narrowed deliberately

One question this document used to leave open is now settled: *how broad should
the paid product be?* Broad agent governance is occupied by vendors bundling it with
enterprise identity, compliance and endpoint stacks. Being a smaller version of that
is not a plan.

So the commercial product is **not** "govern your agents". It is one sentence:

> **Operate and prove the Histos boundary across an organisation.**

Explicitly out of scope, permanently: generic IAM and agent identity, an agent
platform, a competing control specification, a hosted gate on the decision path, and
any security primitive that exists only in the paid tier.

**Sequencing follows from the adoption gate, not from ambition.** A multi-tenant
control plane is a second product — auth, tenancy, retention, certification — and
[`roadmap.md`](roadmap.md) does not permit starting it before external teams keep
this library in production. That constraint is convenient rather than painful,
because the two strongest paid capabilities do not need a control plane at all:
change impact and attack replay both run against a team's own audit log, on their own
infrastructure, inside CI. That is the first commercial shape — no data leaves the
customer, no residency conversation, no dashboard to maintain.

One risk to name while narrowing: **policy lifecycle competes with git.** Staged
rollout, diff, and change history for a text file are things teams already solve with
the tooling they own, and a second source of truth for something living in a
repository is a hard sell. Lifecycle stays on the commercial list, but ranked below
evidence and proof — which have no incumbent — rather than above them.

## What is deliberately *not* claimed

- That the free tier is a trial. It is not time-limited, seat-limited, or
  capability-limited, and it never will be.
- That the commercial tier makes an agent harder to hijack. It does not. It makes
  a hijack visible, provable, and manageable across an organisation.
- That this boundary is the only defensible one. It is the one this project
  commits to.

Related: [`roadmap.md`](roadmap.md) · [`tech-debt.md`](tech-debt.md) ·
[`SECURITY.md`](../SECURITY.md) (what the gate does not protect against at all).
