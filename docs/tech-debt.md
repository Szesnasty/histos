# Known debt

Deliberate shortcuts, in the open. Same principle as
[`../SECURITY.md`](../SECURITY.md): state the limit rather than hide it. Each entry
says what it is, why it is tolerated, and what resolves it.

---

## D1 — The LangChain adapter's live path is untested here

[`integrations/base.py`](../src/histos/integrations/base.py) is framework-free
and fully tested. [`integrations/langchain.py`](../src/histos/integrations/langchain.py)
— the part that reconstructs a `StructuredTool` and preserves `name` /
`description` / `args_schema` — is `# pragma: no cover`, because langchain-core is
not installed and the library has no dependencies.

**The cost:** *"one real call through each adapter is denied by policy and the
framework loop survives"* is unverified. A change to LangChain's tool API would not
break a test. Worse, the question that actually matters — *is there any
tool-execution path that bypasses the gate?* — is not asked by anything automated.

**What resolves it:** langchain-core in the dev extra plus one integration test per
adapter, in a CI job allowed dependencies the library itself refuses.

## D2 — CI does not yet cover the adapters

A workflow now runs ruff, pytest on 3.12/3.13, the conformance corpus, a wheel build,
and `histos validate` / `coverage` / `drift` against the gallery — the gates this
library sells to other people are now gates on this library.

**What is still missing:** the adapter question from D1. CI installs no framework, so
*"is there a tool-execution path that bypasses the gate?"* is still unasked by
anything automated.

## D3 — REVIEW findings are prose, not codes

RUNTIME decisions (`GateDecision.rule`) and POLICY load errors (`PolicyError.code`)
are coded and covered by the conformance corpus. `review_policy` still returns
human-readable strings.

**Why tolerated:** review output is advisory and read by people, so prose costs
nothing today.

**The cost:** policy-analysis tooling — effective permissions, over-provisioning
lint, shadowed rules — needs stable identifiers, and so would any second
implementation wanting to agree about warnings rather than only about verdicts.

**What resolves it:** a REVIEW namespace in
[`../spec/decision-codes.json`](../spec/decision-codes.json), added *with* the
analysis work rather than before it, so the codes describe something real.

## D4 — The confirmation tuple is not complete

An approval is bound to `(tool, canonical args, role, identity)` and is single-use.
The specified tuple also includes **policy hash, expiry, nonce and approver
identity**, and the store is in-process only.

**Why tolerated:** the in-process store is correct for a single deployment, which is
the current target, and it already makes self-approval impossible — the agent cannot
write to the store.

**The cost:** an approval survives a policy change (it should not — after the rules
change a human should re-confirm), and there is no way to carry one across
processes. `confirmation.expires_in` is carried by the *format* but not yet enforced
by the engine.

**What resolves it:** the signed cross-process protocol on the roadmap. It is also a
prerequisite for treating MCP's MRTR as a confirmation transport — MRTR delivers
"someone on the client side answered", which is not a verified approver.

## D5 — Row-level authorization is only enforced where someone authored it

A tool with an RBAC grant and no `resource` block is authorized at the *tool* level:
`get_record(id=victim)` passes, because "this role may call get_record" is true.

**Why tolerated:** the format cannot know which tools have rows. Draft 0.1 removed
the *wrong* constraint from the language; it cannot conjure a *missing* one.

**What mitigates it:** `review_policy` flags every reachable write tool and every
high/critical-sensitivity read tool with no resource constraint, so the gap is loud
rather than silent.

## D6 — Nested arguments are validated shallowly

A `type: object` argument is checked for being an object; its inner fields are not.
Array elements are type-checked and string elements length- and pattern-bounded, but
there is no cross-field or deep-structure validation.

**Why tolerated:** the validator is deliberately tiny so policy evaluation stays
microsecond-scale and simple enough to reason about — a policy bug is an availability
incident here.

**What resolves it:** `nested_schema` and `cross_field_rules`, both demand-pulled and
both needing a shape that does not turn the format into an expression language.

---

## Resolved — kept for the trail

- **The versioning fail-open.** An unknown key in a policy was silently ignored, so a
  policy asking for a check from a newer release loaded cleanly, reported no issues
  from `validate()`, and enforced everything except that check. This was the only
  place in the library where the default was not fail-closed. Closed by the Draft 0.1
  compatibility gate.
- **The IDOR footgun (`source: "call"`).** Comparing a caller-supplied argument to the
  principal proved self-declaration, not ownership. It was documented as DANGER,
  flagged by `review_policy` and refused under `strict` — then removed from the
  language entirely in Draft 0.1, which deleted all three mitigations as dead code. A
  format where the mistake is unexpressible beats one that warns about it.
- **Two divergent `review` implementations.** The library's, and a dependency-free
  copy elsewhere that had drifted from it. Extraction to a standalone repository
  left one.
- **High/critical-sensitivity reads with no resource constraint read as ✓ ready.**
  Tolerated only while the rule would have had to be maintained twice; fixed once
  there was one implementation.
- **Bundle round-trip lost settings.** `strict_returns` and `on_output_violation`
  could not be authored at all; `scan_output_for_canary` loaded but never dumped.
- **Duplicate tool names silently overrode each other.** `tools` became a mapping, so
  a repeat is a duplicate key that canonical parsing already refuses — the
  hand-written check went away with the shape that had required it.
- **Four names for one project.** Settled on Histos before publication.
- **`content_hash` tagged numbers in a way another language could not reproduce.**
  The canonical serializer is type-tagged, so `1` hashed as `["i",1]` and `1.0` as
  `["f","1.0"]` — a distinction Python keeps because `json.loads` does, and one
  `JSON.parse` cannot see at all. A policy writing `maximum: 500.0` would therefore
  have hashed differently in a TypeScript port, and `content_hash` is what policy
  pinning and approval binding rest on, so the divergence would have been silent and
  would have landed on approvals that quietly stopped matching. Closed by rendering
  every number in a fingerprint as decimal text before hashing
  (`canonical_number`), with `numeric-spelling-is-irrelevant` in the canonicalization
  corpus to pin it. **Fixed before publication on purpose:** afterwards it would have
  cost a `schema_version` bump and invalidated every deployed hash. The corpus had
  warned about exactly this case since 0.1.
