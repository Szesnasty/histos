# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **once the public
surface is frozen at v0.3**. Until then, the top-level API may still change
between minor versions — every such change is listed here.

## [Unreleased]

### Fixed — the fourth adversarial pass

The third pass rewrote about 1300 lines. This pass attacked those lines
specifically, and most of what it found was the same shape: a fix aimed at the
attack that was reported, blind to the sibling nobody reported. Nothing here is
a compatibility break for anyone, because nothing is on PyPI yet.

- **`project_output` no longer redacts an entire output because a field held a
  `datetime`.** Every value outside `str/bytes/int/float/bool/None` was routed
  through `on_output_violation`, whose default is redact_all. The projector now
  reads the field names an object publishes — dataclass, NamedTuple, instance
  `__dict__`, so Pydantic too — and drops the undeclared ones, which closes the
  leak the refusal was reaching for without taking correct returns down with it.
  A record keeps its type unless something had to be dropped from it. Slots-only
  objects stay leaves and are named in the trail; SECURITY.md says why.
- **`JSONLAuditSink(strict=True)` now reaches the caller.** `Gate._emit` was the
  library's only caller of `record()`, and its blanket `except Exception` caught
  the strict re-raise and turned it back into a warning — so the flag did nothing
  through `protect()`, `gate()` or `Gate`, while the sink's own warning text
  recommended it as the remedy. `strict` is a public attribute now, so a host sink
  opts in the same way.
- **`Gate.audit_failures`** counts decisions that could not be recorded, whether
  the sink raised or absorbed it. The gap in the trail used to be legible only as
  a RuntimeWarning, which is not something a monitor reads.
- **A lost record no longer becomes a lost call under `-W error`.** The warning
  itself raised, so the totality both sinks document ended at that line.
- **`verify_chain` no longer reports a log this library wrote as forged.** The
  respelling check searched the raw line for a `\uXXXX` escape of a printable
  character; a value holding the *literal text* of one — a regex, a code snippet,
  a Windows path — is serialised as a doubled backslash and five ordinary
  characters, which the search found too. Backslash parity is counted now.
- **Two logs whose paths differ only in case are no longer merged on a
  case-sensitive volume.** The fold was applied on darwin and win32
  unconditionally; APFS can be formatted case-sensitive. It merged two tenants'
  chains, and one tenant calling `rotated()` cleared the other's erasure memory,
  after which erasing that log and appending verified clean. The volume is
  measured per directory now.
- **Ordinary bounded validators load again.** Adjacent repeats over overlapping
  alphabets were refused by *count*, so `^[a-zA-Z]{1,10}[a-zA-Z0-9]{0,20}$` — a
  username validator, 0.00 ms — was refused exactly as `\d+\d+` was. They are
  judged by the product of their caps now, which is what the cost tracks.
  `sources_from_mcp` skips a tool whose pattern will not load, so this was the
  screen deleting the tools it exists to protect.
- **`unique_items` reaches the contract hash**, and is linear rather than
  quadratic. It was missing from `_schema_structure`, so two policies that enforce
  differently shared a `content_hash` and `histos drift` reported CLEAN across the
  flip; and it ran as an equality scan against a growing list at pre-gate step 3,
  costing 461 ms of held CPU for 8 000 distinct elements. **`contract_sha256` and
  `content_hash` move again for any contract using it; regenerate locks.**
- **`histos drift` sees a `servers` repoint on a path item.** OpenAPI resolves
  `servers` at three levels and the importer read two.
- **An `ExceptionGroup` is no longer charged to the chain-depth bound.** A
  40-member `asyncio.TaskGroup` failure came back "chain longer than 16 links" and
  had its real error redacted away.
- **An `async def` yield fixture is no longer refused at setup**, nor is the
  `@asynccontextmanager` workaround the refusal recommends.
- **A malformed OpenAPI node is a refusal, not a traceback.** Seven of eight
  escaped as `AttributeError`, so the per-tool skip did not apply and `histos
  import` wrote nothing. A `requestBody` whose media type this importer cannot
  project is refused too, when it declares named fields — dropping it produced a
  policy that denied every argument the document declares. A byte-stream body
  (`application/octet-stream`, an image) declares no names and still imports.
- **The read-only guarantee reaches all the way down.** `Schema.fields` was a
  plain dict inside a frozen `Schema`, so a field could be replaced in a Gate's
  live ruleset under the pre-edit `policy_hash`; and `Principal.attributes` was a
  `ReadOnlyDict` whose nested containers were writable, so
  `attributes["tenants"].append(...)` edited a bound trust anchor. Nested
  mappings and lists are read-only now (`ReadOnlyList` is a `list` subclass, so
  constraint comparisons are unchanged); a bound tool still receives an ordinary
  mutable copy.
- **`permissions` accepts the spellings `canaries` accepts.**
  `Policy(permissions={"analyst": "read_doc"})` raised an uncaught `TypeError`
  out of `validate()`, which is documented as *returning* structural problems.
- **Re-protecting a tool set no longer fails.** Wrap identity was the unwrapped
  function object, so a bound method — rebuilt on every attribute access — read
  as a different tool, and `gate.policy = tightened` followed by a re-wrap was
  refused at load. Two `functools.partial`s of one function read as the *same*
  tool, which was the same bug pointing the other way. Targets are also held
  weakly now, so a Gate no longer retains every per-request closure it wrapped.
- **A bound outside the type that consults it is refused.**
  `Field(type="string", maximum=10)` and `Field(type="integer", pattern=...)`
  loaded clean and enforced nothing. So did every unsatisfiable twin pair —
  `min_length=10, max_length=5` — which was checked for `min_items`/`max_items`
  only.
- **`$allow_extra` is type-checked rather than coerced.** `bool("no")` is True,
  so `$allow_extra: no` — the natural way to write "closed" in YAML, where this
  loader deliberately keeps `no` a string — opened the argument surface. An
  argument literally named `$allow_extra` is refused at dump time.
- **The suppressed-exception scan reaches every hidden branch**, matches both
  canary tiers, and honours the per-tool `scan_output_for_canary` switch. It ran
  at the top level only, so a repository hiding a driver error under a service
  that wraps the repository was inspected by neither pass.
- **A `$ref` sibling composes by conjunction.** It could downgrade `x-sensitive`
  from `secret` to `pii`, delete a numeric bound via a no-op draft-04 boolean,
  and replace `properties`/`required` instead of taking the union.
- **`list[Optional[str]]` imports as an untyped element** instead of narrowing to
  `string` and denying every null the source allows; and the null-only sentinel
  no longer leaks into `item_type`, where it made every element type pass.
- **A `Principal` attribute holding a cycle no longer raises**, and the snapshot
  keeps `defaultdict`, `Counter`, `OrderedDict` and namedtuples as themselves.

## [0.1.0] - 2026-08-12

### Changed — behaviour, before anything is published

An adversarial pre-release review found these, and each is a change of behaviour
rather than a bug fix. None of it is a compatibility break for anyone, because
nothing is on PyPI yet — which is exactly why they land now rather than in 0.2.

- **`contract_sha256` and `schema_sha256` move.** `nullable`, `item_enum`,
  `min_items`, `max_items` and `unique_items` are all now part of the hashed argument
  shape — each of them is a bound a caller can violate, so each belongs in the hash —
  and the recorded
  source shape now covers the whole tool object: for MCP everything beside the two
  schemas — `title`, `annotations`, `_meta` — and for OpenAPI the `servers` the call
  actually goes to. A vendor could previously rewrite any of those after review and
  `histos drift` reported clean. **Every lock file must be regenerated with
  `histos import`.** The conformance corpus and the MCP demo's lock are regenerated
  in this release.
- **A positional call is bound by name instead of refused.** Gated tools were
  silently keyword-only. `*args`, and a callable exposing no signature, are still
  refused — now as an audited `unnameable_args` denial rather than an unrecorded
  `PolicyError`.
- **`confirm` must return exactly `True` to approve.** Any other truthy value —
  a response object, an approval record, the string `"denied"` — is now a
  `confirm_error` denial.
- **`principal=` is gone.** Use `use_principal()` per request, or `fixed_principal=`.
  The deprecation warning it used to emit was filtered by default outside `__main__`,
  so the misconfiguration it warned about was silent in every real host. (Entries below
  this heading that describe `principal=` as deprecated-but-working predate that and
  describe the state before 0.1.0, not the release.)
- **`ApprovalStore(policy)` takes its policy positionally and required.** Built
  without one it could not see `confirmation.expires_in`, so a declared window
  silently did not exist.
- **`use_principal()` refuses to open inside a generator.** A generator has no
  context of its own, so the binding leaked into the caller and interleaved streams
  could run as each other. The refusal reads the call stack and is therefore
  best-effort: a hand-written scope object that takes it in an `__enter__` of its own
  interposes a frame the check cannot distinguish. SECURITY.md scopes the guarantee.
- **`Gate.wrap()` refuses a callable that is already gated**, and `protect()` refuses
  two tools sharing one `__name__`, or a lambda.
- **A Gate's ruleset is read-only.** `gate.policy.permissions[role] |= {...}` took
  effect immediately while every audit record kept naming the hash from before the
  edit. Swap the whole policy with `gate.policy = ...`, which re-hashes.
- **`histos review` exits 1 on a structural issue**, matching `histos validate`, and
  prints its warnings rather than counting them.
- **The pattern screen refuses polynomial shapes, not only exponential ones.** A
  `pattern` in a policy or an imported schema is now refused at load when adjacent
  repeats can match the same character (`^[A-Za-z0-9]+[A-Za-z0-9_-]+[A-Za-z0-9]+$` cost
  48 s on one 4 KiB argument) or when a delimited-line shape leaves every delimiter a
  free choice (`^.+,[^\n]+,[^\n]+$`, 518 ms at 2 000 characters). A load-time timing
  probe backs the shape screen up. Patterns that loaded before may now raise
  `PolicyError`; the message names the rewrite. Verified against 60 real-world patterns
  in `tests/corpus/patterns.json`, each classified by measurement rather than by eye.
- **The importer refuses more, and drops less.** An unknown JSON Schema `type`, a
  near-miss `x-sensitive` marker, and a tool name carrying a terminal control
  character are all refused rather than silently degraded.
- **The PAN detector requires an issuer prefix** as well as a Luhn-clean run, so
  IMEIs and ordinary Luhn-clean reference numbers are no longer redacted as cards.

### Added

- `histos --version`.
- `JSONLAuditSink.rotated()` — tell a sink its log was rotated deliberately, so
  the next chain starts clean. Rotation and erasure are indistinguishable on disk,
  so this is an explicit call rather than something inferred from the file: it is
  the one signal an attacker rewriting files cannot produce. SECURITY.md used to
  offer "rotate the `.tip` sidecar with the log", which did nothing.
- `JSONLAuditSink.failed` — records this sink could not write, counted rather than
  raised. See the `Fixed` entry below. `JSONLAuditSink(..., strict=True)` opts back
  into raising, for a host whose evidence requirement outranks its availability.
- `output_budget=` on `gate()` and `protect()`, not only on `Gate`. The remedy for a
  tool that legitimately returns more than the scan budget is to raise the budget, and
  it was reachable only from the class API the README does not teach.
- `unique_items` on `Field`, projected from JSON Schema `uniqueItems` — what every
  pydantic `set[T]` emits, and previously a whole-tool refusal.
- `unsafe_pattern` joins the published policy-code vocabulary, and five pattern
  refusals join the conformance corpus. The ReDoS screen is the release's largest new
  refusal class and the normative artifacts did not know it existed — `spec/` still
  described `pattern` as "NOT ReDoS-safe".
- `audit_key=` on the `gate()` and `protect()` one-liners, so a stable
  `args_digest` no longer requires constructing a `Gate` by hand.
- `nullable` on `Field`, inferred from `T | None` and from `anyOf: [T, null]`.
- `GateConfirmationRequired.request` and `.fingerprint` — the arguments an approval
  will actually cover, which a host holding only its own arguments cannot derive
  when the tool has a `bind`.
- `uninspectable_output`, `unnameable_args` and `confirm_suspended` decision codes.
- Python 3.14 is tested and declared. The supported range is 3.12 – 3.14.
- macOS and Windows are tested, not only asserted by the `OS Independent`
  classifier. Two guarantees are POSIX-shaped and remain so, both documented in
  SECURITY.md: the audit log's cross-process `flock`, and its owner-only `0o600`
  creation mode. On Windows the sink degrades to in-process locking rather than
  failing, which is what the suite now runs and checks.

The engine as first extracted into its own repository: RBAC with role
inheritance, argument-schema validation, resource-aware (Cedar-style) constraints
with IDOR-block-by-default, trusted argument binding, rate/budget limits,
out-of-band single-use confirmation, canary detection, structured secret
detectors, output projection and redaction, hash-chained audit,
`observe`/`enforce` modes, shape importers (MCP / OpenAPI / JSON Schema / Python
signature), policy review, the `histos` CLI, and LangChain / LangGraph
adapters. Zero runtime dependencies.

### Fixed — security

- **The gate no longer publishes a route to the ungated tool.** `functools.wraps`
  sets `__wrapped__` to the callable being wrapped, so `gate()`, `Gate.wrap()` and
  `protect()` each handed out a public pointer at the *unprotected* function —
  followed automatically by `inspect.unwrap`, `inspect.signature(follow_wrapped=True)`
  and every decorator-aware framework, and by this library's own `_unwrap_target`.
  A `viewer` refused by RBAC could call `wrapped.__wrapped__(...)` and the tool body
  ran, with no decision and no audit record. This was fixed once in the LangChain
  adapter and documented as closed; the core paths — the ones the README quickstart
  shows — still had it. Metadata is now adopted attribute by attribute
  (`_adopt_metadata`), which also stops `WRAPPER_UPDATES` from republishing a callable
  object's `self.func`. `__closure__` traversal remains out of scope and is now stated
  as such: a wrapper must hold what it wraps, and reaching it means in-process code
  the trust model already excludes.
- **`content_hash` is injective again.** `Policy.fingerprint` flattened every number
  to bare text, so `value: 1` and `value: "1"` — two policies that reach *opposite*
  verdicts — produced one hash. It is now taken over the type-tagged canonical form.
- **`content_hash` is deterministic across processes.** Set-valued fields were
  serialised in Python's iteration order, so the same `Policy` hashed differently
  under different `PYTHONHASHSEED` values, silently unbinding approvals issued by one
  worker from every other worker.
- **The tool lock sees a retyped enum.** `schema_sha256` and `contract_sha256` were
  taken over the flattened projection, so a server reshipping `enum: [1, 2]` as
  `enum: ["1", "2"]` — which inverts which calls the tool accepts — matched byte for
  byte and `histos drift` exited 0. That is the MCP rug-pull the lock exists for.
  Hashes are now taken over `ToolContract.shape_structure()`; the published
  `shape_fingerprint` projection is unchanged.
- **An inferred argument schema is no longer mistaken for a policy.**
  `protect(infer_missing=True)` — the default — installed a schema inferred from the
  signature even when that schema could reject nothing (`**kwargs`, unannotated
  parameters), which turned the documented `unknown_tool` / `no_arg_schema` denial
  into ALLOW while the coverage report still said `needs-policy` about a tool that had
  just run. It is now installed only when it actually constrains.
- **A streaming tool is refused at wrap time.** A generator or async generator returns
  its iterator immediately, so the post-gate inspected the iterator object and reported
  `allow` while every value the tool yielded flowed past uninspected.
- **`gate.policy = …` takes effect.** `Engine` kept its own reference, so reassigning
  the policy read like a revocation and enforced the old ruleset forever.
- **A `Gate` no longer rewrites its caller's `Policy`.** `protect()` mutated the
  `tools` dict in place — `Policy` is frozen, the dict it points at was not — so one
  gate's inference changed authorization for every other gate holding that object, and
  moved its `content_hash` underneath them.

### Changed — breaking

- **Every policy hash, lock hash and conformance fixture hash changed** as a
  consequence of the two `content_hash` fixes above. `conformance/projection`,
  `conformance/manifest.json` and the gallery table in `policies/README.md` were
  regenerated; the projections themselves are byte-identical, and the two relations
  the corpus makes normative still hold (`8` and `8.0` share a hash; unprojected
  keywords move `schema_sha256` and not `contract_sha256`). Nothing has been
  published, so no policy in anyone's repository is affected.
- **`content_hash` renders numbers as decimal text before hashing.** The canonical serializer is type-tagged: `1` hashed as
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

[Unreleased]: https://github.com/Szesnasty/histos/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Szesnasty/histos/releases/tag/v0.1.0
