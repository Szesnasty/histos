# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **once the public
surface is frozen at v0.3**. Until then, the top-level API may still change
between minor versions — every such change is listed here.

## [Unreleased]

### Changed — breaking

- **`content_hash` now renders numbers as decimal text before hashing, so every
  policy hash changed.** The canonical serializer is type-tagged: `1` hashed as
  `["i",1]` and `1.0` as `["f","1.0"]`. Python preserves that distinction because
  `json.loads` does; `JSON.parse` collapses both to one number, so a second
  implementation could not have reproduced these hashes at all. Since `content_hash`
  is what policy pinning and approval binding rest on, the divergence would have been
  silent and would have surfaced as approvals that stopped matching between services.
  Fixed **before** publication deliberately — afterwards it would have cost a
  `schema_version` bump and invalidated every deployed hash. Pinned by
  `conformance/canonicalization/numeric-spelling-is-irrelevant.json`. Nothing has been
  released, so no policy in anyone's repository is affected; the gallery hashes in
  `policies/README.md` were regenerated.
- **Renamed to Histos.** Import `histos`, install `histos`, CLI
  `histos`. Nothing was ever published under the old names, so there is no
  migration path and none is owed.
- **Policy Format Draft 0.1** (`schema_version: histos.policy/0.1`), adopted and
  implemented — see [`docs/policy-format-draft-0.1.md`](docs/policy-format-draft-0.1.md)
  for the six decisions and why each went the way it did:
  `tools` is a mapping keyed by name · `bind: {arg: principal.attr}` replaces the
  `bindings` list, with the value grammar frozen at exactly `principal.<attr>` ·
  `resource: {owns, where}` replaces `constraints` · `confirmation` and `output`
  group what used to be six flat keys.
- **`Constraint` can no longer compare a call argument** — `source=` is gone and every
  constraint is resource-bound. Each previous use of it was either redundant with the
  argument schema (`amount le 1000` is `amount: {maximum: 1000}` written worse, since
  it skipped type validation and hid the bound outside the tool contract) or the
  confused-deputy IDOR that `review_policy` warned about. **A format where the
  dangerous construct is unexpressible beats one that warns about it** — so
  `self_declared_authz`, its review warning and its strict-mode refusal were all
  deleted as dead code. `review_policy` now flags a *missing* constraint instead,
  including on high/critical-sensitivity reads.
- `ProtectResult.report` → `.coverage`; `principal=` → `fixed_principal=`.

### Added

- **Conformance corpus** ([`conformance/`](conformance/)) — decisions,
  canonicalization and invalid-policy fixtures, run by the reference engine's own
  test suite so a Python change that breaks the contract fails Python's CI today
  rather than a future port's much later. Canonicalization is covered because that is
  where implementations actually diverge: not on a verdict, but on whether two
  spellings of one policy hash the same, which is what policy-hash-bound approvals
  depend on.
- **`PolicyError.code`** — a POLICY namespace distinct from the RUNTIME decision
  rules, because "this policy cannot be loaded" and "this call is refused" are
  different answers and a conformance suite must tell them apart.
- [`docs/design.md`](docs/design.md) — one public design document replacing the
  four internal specs that preceded it.

### Security
- **A raising tool no longer escapes the POST chain.** `result = tool(**args)` sat
  outside any `try`, so an exception skipped the post-gate entirely: a canary token or
  a recognised secret in the error message reached the caller — and therefore the
  model — verbatim, while the audit trail recorded only the pre-decision and never the
  fact that the call had ended by raising. An exception is the *other* way a tool
  returns content, so it now runs through the same content controls as a return value,
  under the same `output` settings. New decision code **`exception_redaction`** (RUNTIME,
  post phase) and new exception **`ToolErrorRedacted`**, raised only when something was
  actually removed; otherwise the original propagates untouched with its traceback
  intact. The original is deliberately not attached as `__cause__` *or* `__context__` —
  its `args` still hold the unredacted text and anything formatting an exception chain
  would print it straight back out, so the re-raise happens outside the handler rather
  than relying on `from None`, which only suppresses the display. Projection, strict
  returns and sensitive-field redaction do not apply: all three need a declared return
  shape an exception does not have. `SECURITY.md` states the residual, which is the
  canary limit again — verbatim and structural matching only.
- **Policy loading no longer fails open on anything it does not understand.** An
  unknown key (at bundle, tool, field, constraint, binding or role level), an
  unsupported `schema_version`, or a capability listed under `requires.features`
  that this engine does not implement now raises `PolicyError` instead of being
  silently ignored. Previously a policy asking for a check from a newer release —
  `url_egress_allowlist`, say — loaded cleanly, reported no issues from
  `validate()`, and enforced everything *except* that check. On a fleet running
  mixed versions, half the deployments would silently stop enforcing a control the
  policy asks for. This was the only place in the library where the default was not
  fail-closed.

### Added
- `requires.features` in the policy bundle — a policy declares the capabilities it
  depends on and the engine must prove it implements them, or refuse to load. This
  is the portable contract: an *engine version* stops being a usable contract the
  moment more than one implementation exists. Introspect the registry via
  `histos.ENGINE_FEATURES`. Declaring `requires` does not change the policy's
  `content_hash` — it is a load-time assertion, not policy content, so adding one
  must not invalidate approvals bound to the hash.
- [`docs/open-core-boundary.md`](docs/open-core-boundary.md) — where the open/closed
  line runs and how to decide for capabilities that do not exist yet. Every
  deterministic check, including distributed enforcement, is permanently Apache-2.0.
- `load_policy(path_or_dict)` — canonicalized policy loading. Rejects
  duplicate keys in both JSON and YAML rather than silently taking the last one,
  and normalizes YAML's `yes`/`no`/`on`/`off` surprises instead of coercing them.
  The same logical policy in YAML and JSON produces the identical `content_hash`.
- Top-level `protect(tools, *, policy, ...)` returning a `ProtectResult` with
  `.tools` / `.coverage` / `.review`.
- `mode="enforce"|"observe"` as the public spelling on `gate()`, `protect()` and
  `Gate`. `enforcement=` remains accepted.
- Observe-mode audit records now carry `executed`, so a watched-but-not-blocked
  decision reads `effect=deny enforced=false executed=true` and cannot be
  mistaken for a block.
- **Async support**: `gate()` / `protect()` auto-detect a coroutine tool
  and return an `async` wrapper. Detection unwraps decorators, follows
  `functools.partial`, and inspects a callable object's `__call__`; a genuinely
  ambiguous target fails loud at wrap time. `resource_resolver` and the `confirm`
  callback may be sync or async on the async path.
- PEP 561 `py.typed` marker — downstream type-checkers now see the annotations.
- `examples/security.policy.yaml` — the portable bundle the README, the CLI and
  the specs all refer to.
- Repository furniture: `LICENSE` (Apache-2.0), `.gitignore`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, vulnerability-reporting section in `SECURITY.md`, and full
  PyPI metadata in `pyproject.toml`.

### Changed
- `gate()` / `Gate.wrap()` / `Gate.protect()`: the wrap-time principal kwarg is
  now `fixed_principal=`. The old `principal=` name read like the
  per-request path but binds **one identity forever** — on a multi-tenant server
  that means every caller runs as that identity. It still works and still does the
  same thing, but it now emits a `DeprecationWarning`; `use_principal()` remains
  the primary path.
- `ProtectResult.report` is now `ProtectResult.coverage`. `.report` is kept as an
  alias for one release.
- Documentation is scoped to this standalone repository: dead links into the
  earlier layout (`../apps/...`, `../packages/histos/`) are gone, hard-coded
  test counts that had drifted across four documents are gone, and `tech-debt.md`
  now distinguishes debt that lives *here* from debt that left with the extraction.

## [0.1.0] — unreleased

The engine as first extracted into its own repository: RBAC with role
inheritance, argument-schema validation, resource-aware (Cedar-style) constraints
with IDOR-block-by-default, trusted argument binding, rate/budget limits,
out-of-band single-use confirmation, canary detection, structured secret
detectors, output projection and redaction, hash-chained audit,
`observe`/`enforce` modes, shape importers (MCP / OpenAPI / JSON Schema / Python
signature), policy review, the `histos` CLI, and LangChain / LangGraph
adapters. Zero runtime dependencies.

Not yet released to PyPI — see `docs/roadmap.md` for what gates that.
