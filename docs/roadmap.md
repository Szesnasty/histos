# Roadmap

What the **library** will do, in order. No dates on purpose — this is a sequence,
not a schedule, and most of it is demand-pulled.

This is the open-source roadmap. Where a capability sits relative to the commercial
control plane is settled separately and permanently in
[`open-core-boundary.md`](open-core-boundary.md): **every deterministic check on this
page is and will remain Apache-2.0**, including distributed enforcement.

Legend: `[x]` shipped · `[ ]` todo · 🚦 a gate not crossed until it passes.

---

## Shipped

**Enforcement**
- [x] RBAC with role inheritance, deny-by-default, unknown-tool deny
- [x] Argument schema: type / required / enum / lengths / pattern / numeric range /
      array elements / non-finite refusal
- [x] Row-level authorization against the resolved resource; `owns` sugar, and the
      self-declared-argument form removed from the language entirely
- [x] Trusted argument binding — the model cannot choose a bound value
- [x] Rate and budget limits, consumed atomically at the point of execution
- [x] Out-of-band confirmation: single-use, bound to the exact action
- [x] Canary (verbatim + normalized) and checksum/structural secret detectors
- [x] Output projection, strict returns, sensitive-field and secret redaction
- [x] Exception redaction — a raising tool goes through the POST chain too, so an
      error message is not the one way out of the process that skips redaction
- [x] Fail-closed everywhere; `observe` / `enforce` with `executed` in the record
- [x] Async: coroutine tools auto-detected, async resolver and confirm callbacks

**The contract**
- [x] Policy Format Draft 0.1 — `tools` as a mapping, `bind`, `resource.owns`/`where`,
      `confirmation`, `output`
- [x] Canonical loading: duplicate keys refused, YAML 1.1 bool set normalized, YAML
      and JSON hash identically, defaults normalized away
- [x] Compatibility gate: unknown keys, `requires.features`, `schema_version` — a
      policy this engine only partly understands is refused, never partly enforced
- [x] Decision vocabulary in RUNTIME / POLICY namespaces
- [x] Conformance corpus — decisions, canonicalization, invalid-policy, projection —
      running in this engine's own test suite

**Around it**
- [x] Importers: MCP / OpenAI tools / OpenAPI / JSON Schema / Python signature
- [x] `review_policy` tri-state; `coverage` as a CI gate
- [x] Hash-chained audit with a verifier
- [x] `histos` CLI: validate / review / coverage / explain / import / drift / audit verify
- [x] CI — ruff check and format, pytest on Python 3.12–3.14 across Linux, Windows
      and macOS including the conformance corpus, the wheel installed bare to prove
      the zero-dependency claim, and `validate` / `review` / `coverage` / `drift` run
      against the gallery. The gates this library sells to other people are now gates
      on this library.
- [x] **Contract drift detection** — `histos drift` fails on a tool definition that
      moved since it was reviewed, `histos import --update` refreshes `args`/`returns`
      without touching the security semantics, and a sidecar lock records three hashes
      per tool (shape, description, projected contract) so a rewritten description is
      reported without being mistaken for an enforcement change. Provenance stays out
      of the policy: the artifact remains self-contained and its `content_hash`
      untouched. Normative in `spec/tool-lock-0.1.schema.json` and
      `spec/json-schema-projection-0.1.md`, pinned by the `projection/` corpus. Design
      and the rejected alternatives: [`tool-contracts.md`](tool-contracts.md).
- [x] LangChain and LangGraph adapters over a framework-free core
- [x] **Killer demo** — *Hijacked. Still bounded.* Five applications compare the
      same task with and without a policy and judge damage from datastore state.
- [x] **Verify the real chokepoint** in LangChain and LangGraph — the live mediation
      harness drives public, private and async execution paths plus a compiled
      LangGraph `ToolNode`; it found a real bypass and now guards the regression.
- [x] `[project.urls]` — Homepage / Repository / Issues / Changelog, carried into the
      wheel metadata, so PyPI links where the code actually is.
- [x] **Draft 0.1 published with the engine** — schema, decision codes, versioning
      rules and conformance fixtures ship in the source distribution; the editor
      schema is also served at `usehistos.dev/spec/policy-0.1.schema.json`.
- [x] **Policy-authoring path** — a complete policy on PyPI, a focused writing guide,
      seven checked YAML/JSON examples and generated key reference.

---

## Next

- [ ] **MCP as one product flow**, never an adapter now and DX later:
      `tools/list` → infer contracts → generate policy → observe → suggest → human
      review → enforce. An MCP server exposing twenty tools makes cold start *worse*,
      so generation ships with the adapter or neither ships.
- [ ] **MRTR confirmation, experimental** — carrying the full approval tuple. MRTR is
      a transport; the approval is the security decision, and the two must not merge.
- [ ] **Call-sequence constraints, designed before implemented** — one observed attack
      split a secret across individually legal calls, so per-call checks and volume
      budgets were insufficient. Find the smallest deterministic state model that
      blocks composition without turning the policy into a workflow language.

## 🚦 Adoption gate — nothing below starts until this passes

- [ ] **5–10 external teams protect a real agent and keep it** — still running weeks
      later.

Published deliberately: it is a commitment not to pad the library with features
nobody asked for and call that progress.

## After the gate

Ordered by pull, not preference. The signal that would pull each one is in parentheses.

- [ ] **Canonical decision evidence, opt-in** — a record carrying what a decision was
      made *from*, not only what was decided: principal snapshot including attributes
      and `can_view`, canonical arguments, the resolved resource, policy hash, engine
      version, conformance profile, PRE and POST outcomes — **and the mutable context
      the decision actually read**: budget consumed, rate-window count, approval state,
      and the evaluation time the window is measured against. Steps 1–6 of
      `Engine.decide` are pure; step 7 calls `limits.check` and confirmation consults a
      single-use store, so a record without that context reproduces most of a decision
      and silently guesses the rest. The audit record deliberately cannot serve here —
      `digest_args` is a keyed HMAC and the resolved resource is never stored.
      Separate record, separate privacy posture, never on by default. *(first team that
      has to answer "what would this policy change have done?")*
- [ ] `url_egress_allowlist` (SSRF: host allowlist, block private/link-local)
- [ ] `path_containment`, `unicode_safety`, `structural_caps`, `string_bounds`,
      `format_validators`
- [ ] `cost_budget`, multi-window `rate_limit`, `limit_scope`, shared limit backend
      *(first multi-replica deployment)*
- [ ] Signed cross-process confirmation: policy hash, expiry, nonce, approver identity
      *(first multi-process deployment, or the first auditor asking)*
- [ ] `dry_run_simulate`, `policy_analysis` — effective permissions, over-provisioning
      lint *(first policy-CI ask)*
- [ ] REVIEW decision codes — currently prose; a prerequisite for that analysis tooling
- [ ] Adapters: OpenAI Agents. Importers: Pydantic
- [ ] `cross_field_rules`, `checksum_formats`, `nested_schema` *(first structured tool)*
- [ ] Audit export: OTel / CloudEvents / OCSF
- [ ] **TypeScript implementation** passing the same conformance corpus

## Research — validate before committing

- [ ] ReBAC (bounded-depth relationship tuples)
- [ ] Cedar / OpenFGA interop, fenced off from the conformance guarantee
- [ ] Taint-label propagation (needs a value-tracking runtime — not zero-dependency)

---

## Permanently out of scope

Semantic judgement never enters this layer: meaning-level injection detection,
paraphrased or multi-round-encoded exfiltration, free-text PII with no structure,
entropy-flagged unknown secrets, "is this action sensible". These are probabilistic
and belong to a different tier, reached through the `escalate` seam — which
**collapses to DENY when nothing is wired to it**, so the deterministic core is never
weakened in order to add semantics.
