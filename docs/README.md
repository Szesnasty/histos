# Histos documentation

The main [README](../README.md) explains why Histos exists and gets a tool behind a
policy. Use this page to go deeper without turning the project landing page into a
manual.

## Start here

- [Security model](../SECURITY.md) — the guarantee, required trust and where it stops.
- [Identity](identity.md) — bind a principal from an authenticated host context.
- [Policy gallery](../policies/README.md) — seven worked YAML/JSON policies.
- [Policy reference](policy-reference.md) — every supported key, generated from the
  schema.

## Adopt it safely

- [Tool contracts and drift](tool-contracts.md) — import existing tool shapes and
  detect changes after review.
- [Design](design.md) — the decision path, resource authorization and enforcement
  invariant.
- [Demo report](../demo/README.md) — scenarios, methods, results and policy costs.

## Implement the contract

- [Policy Format Draft 0.1](policy-format-draft-0.1.md) — design decisions and
  compatibility rules.
- [`spec/`](../spec/) — schemas, decision vocabulary and normative projection.
- [`conformance/`](../conformance/) — language-neutral fixtures and passing levels.

## Project decisions

- [Roadmap](roadmap.md) — shipped work, next work and the adoption gate.
- [Known debt](tech-debt.md) — deliberate limitations and their exit criteria.
- [Open-core boundary](open-core-boundary.md) — what stays open and what a future
  commercial control plane may operate.
- [Contributing](../CONTRIBUTING.md) and [changelog](../CHANGELOG.md).
