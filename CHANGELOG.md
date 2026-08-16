# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **once the public
surface is frozen at v0.3**. Until then, the top-level API may still change
between minor versions — every such change is listed here.

## [0.1.1](https://github.com/Szesnasty/histos/compare/v0.1.0...v0.1.1) (2026-08-16)


### Bug Fixes

* **docs:** teach policy authoring on PyPI ([4915e06](https://github.com/Szesnasty/histos/commit/4915e06f7313d7a8f9c959d9586272cf1cdf4d30))

## 0.1.0 (2026-08-16)


### Features

* ship deterministic agent tool-call enforcement ([0632ab8](https://github.com/Szesnasty/histos/commit/0632ab82c8e626e8781a57a6c7972f0bcebe1029))


### Documentation

* label demo fixtures as synthetic ([d4cb261](https://github.com/Szesnasty/histos/commit/d4cb261d53987c0a2cafe312188fab1224e8a2a6))
* use final website domain ([b7e10b7](https://github.com/Szesnasty/histos/commit/b7e10b763d83fa4635e28104fde3c9210ccd1812))

## [Pre-release history]

### Fixed — publication-blocking audit

- PyPI metadata now presents one durable `pip install "histos[yaml]"` instruction
  instead of freezing pre-release caveats into the immutable project description.
- Unpatterned text can use the host's configurable aggregate input budget; only values
  actually evaluated by Python `re` retain the 4,096-character safety ceiling.
- Optional content rules scan the complete bounded argument blob, so padding before an
  injected instruction can no longer move it beyond an 8,000-character prefix.
- Regex-parser internals load only when a patterned field is constructed. The rest of
  Histos remains importable without CPython's private parser; a pattern then fails
  closed if its structural safety screen is unavailable.
- `LimitStore(max_keys=...)` now bounds attacker-selected identity/tool cardinality,
  reclaims expired rate-only keys, and exposes an explicit `forget()` operation for
  identities whose lifetime-budget state may safely be retired.
- The demo setup now pulls every model used by its published comparison table, and
  release automation, verification diagnostics and public API signatures agree with
  the behavior they describe.
- Aggregate input size is refused before a trusted resource resolver receives the
  arguments, on both sync and async paths. Oversized input can no longer trigger host
  IO that the deterministic chain already knows it will deny.
- Every third-party GitHub Action is pinned to a commit and updated through Dependabot.
  Publication runs only after Release Please creates a release; rebuilding an existing
  tag is a separate, explicit manual recovery path that verifies the exact checkout.
- Hosted-demo endpoints now reject non-HTTP schemes, embedded credentials and remote
  clear-text HTTP before reading an API key or sending prompt content.

### Changed — release presentation

- The project README is now a short product entry point instead of a long manual:
  enforcement thesis, measured evidence, install, one working example and the
  production boundary. It explicitly names the clinic policy's feature cost and keeps
  model-dependent demo results separate from deterministic controls.
- `docs/README.md` is the documentation map. The roadmap and known-debt inventory no
  longer list the shipped demo and live framework mediation harness as unfinished.

### Fixed — final release audit

- Semantic escalation now accepts exactly the boolean `True`. Truthy response
  objects, dictionaries and strings such as `"denied"` can no longer release a call;
  non-boolean verdicts become an `escalation_error` denial.
- Rate-limit windows and injected clocks must be positive and finite, so NaN or a
  negative configuration cannot silently turn a declared rate limit off.
- Import, contract merge and lock generation now refuse duplicate tool names instead
  of letting untrusted list order choose the reviewed definition and erase its sibling.
- Audit sink and optional content-rule switches now validate exact booleans and usable
  capacities/keys at construction time.
- OpenAI provenance now hashes non-projected source fields (including `strict` and the
  outer tool container), and MCP/OpenAI/OpenAPI importers distinguish malformed present
  fields from absent ones. The changed normative source shape is corpus `0.6.0`.
- Approval and rate-limit clocks now reject non-finite values; approval clocks also
  reject backwards movement, while a backwards limiter clock conservatively retains
  calls for longer instead of reopening the window;
  OpenAPI server inheritance preserves an explicitly empty nearest-level declaration,
  and policy review includes roles declared only as inheritance children.
- Python policy constructors now validate their full object graph (schema entries,
  contract names/types, bindings, constraints, role/grant maps and metadata) before a
  malformed value can crash hashing or evaluation. Import and lock parsers likewise
  turn hostile container types into controlled diagnostics.
- Imported source snapshots, lock maps and reviewed lock evidence are detached from
  caller-owned dictionaries after validation. A later edit can no longer rewrite the
  human-readable baseline while leaving the already-computed hashes unchanged.
- OpenAPI import now rejects malformed parameter objects, names, locations and
  present-but-non-object schemas/content; it also validates path parameters and
  request-body booleans instead of silently weakening their projection.
- `SECURITY.md` now describes the shipped resource-only constraint language; the
  removed `source="call"` API is no longer presented as a current default.
- Policy blocks that are present but malformed (`null`, a list, a scalar, or a
  missing/non-boolean `required`) are now rejected instead of being collapsed to an
  empty block. All security switches are exact booleans in both bundle and Python APIs,
  and array `item_type` is validated eagerly.
- Approval expiry is pinned to the paused `GateRequest`, so an `ApprovalStore` that
  survives a `Gate.policy` hot reload enforces the window the approver actually saw.
  The request form, `store.grant(exc.request)`, is now the documented default.
- Complete-mediation reports distinguish wrappers produced by different Gate instances
  and verify the exposed name against the contract name. An explicit `wrap(name=...)`
  now publishes that name to frameworks.
- Cancellation while a synchronous or asynchronous confirmation callback is pending is
  recorded as `confirm_cancelled`; cancellation in a resource resolver or semantic tier
  is recorded as `pre_cancelled`. Both carry `executed=false` and propagate unchanged.
- Audit-chain verification now returns a diagnostic instead of raising for non-object
  JSON records, invalid UTF-8, directories, and filesystem read failures.
- Tool-lock parsing now enforces required maps, evidence hashes, reviewed copies and
  exact field types, and its published JSON Schema now describes both readable version
  1 and current version 2. OpenAPI parameter `required` is also an exact boolean rather
  than a Python-truthiness coercion.

### Fixed — the sixth adversarial pass

The fifth pass rewrote about 430 lines of the engine. This pass attacked those
lines, and then attacked its own. Eight of the thirteen findings were two shapes
wearing different clothes — two passes over one value where only one carried a
guard, and a key or an enumeration doing a job one thing cannot do — so those two
shapes are now asked as properties over the whole surface on every run rather
than looked for by hand.

- **A canary on a leaf's attribute reached the caller in the *default*
  configuration**, with `effect=allow` and an empty `redactions`. The projector
  must not enter a leaf — reading `class Money(str)`'s attributes shreds
  `Money("12.30")` into `{"currency": "EUR"}` — and the scanners inherited that
  refusal although their job is the reverse. The sixth distinct shape a canary
  has escaped in; an inherited `__slots__` was a seventh, found in the fix for
  the sixth an hour later.
- **`deny_secret_args` was bypassed by one invisible character.** It is on by
  default and refuses a card number, an IBAN or a decodable JWT in an argument.
  One U+00AD SOFT HYPHEN split every pattern, and all 170 Unicode format
  characters walked a PAN into the tool. The detectors now read the text twice,
  and only when something invisible is actually in it.
- **The canary scan stripped five invisible characters where the rule covers
  170**, including the tag block `U+E0020`–`U+E007F` that mirrors ASCII
  invisibly. A test regenerates the table from the running Python and fails,
  naming the character, if a Unicode release adds one.
- **Two policies that enforce differently shared one `content_hash`** — the hash
  an approval binds to, the lockfile pins and drift detection compares.
  `multiple_of` ran exact modulo only when both sides were `int`; the other path
  is `isclose(rel_tol=1e-9)`, a window about a billion wide at 1e18.
- **A cyclic or very deep argument reached the caller as a `RecursionError` with
  nothing written to the trail** — no execution, but no decision and no record
  either, which is an absence rather than a denial. `canonical_json` refuses a
  cycle and refuses nesting past 200, and the audit digest's fallback no longer
  walks the structure the serializer just refused.
- **An identity stayed bound after every scope holding it had closed.** `with` is
  LIFO and cannot cause it; a middleware entering on request-start and exiting on
  response-end can, with two overlapping requests in one context.
- **A legal JSON Schema took its whole tool down.** `{"minimum": 1, "maximum":
  100}` with no `type` is ordinary and is what many MCP servers emit; a guard
  against dead bounds turned it into a `PolicyError`. Bounds are dispatched on
  the value now, exactly as the string bounds beside them always were.
- **A form body naming fields more than four `$ref` levels down was dropped in
  silence**, which is the failure that walk exists to prevent.
- **`sensitivity`, `rate_limit`, `budget` and `confirmation_expires_in` are
  checked where the contract is written**, not where it is hashed or called.
  `budget: "many"` used to build fine and answer `internal_error` to every call
  for the life of the process.
- **`SECURITY.md` described a weaker library than the one that ships.** Two
  passages said a canary in a dataclass field, a NamedTuple, an instance
  `__dict__` or an attribute on a `str` subclass is not reached by the output
  scan. All four are reached. Understating a control is still a document that is
  wrong.

### Changed — the sixth pass

- **The lock's write key and its erasure memory are keyed apart.** They want
  opposite things — the memory must survive `rm -rf logs && mkdir logs`, the lock
  must collapse every spelling of one file — and one key could only ever satisfy
  one of them, which it did, alternately. A macOS firmlink or a Linux bind mount
  gave one log two locks and interleaved appends into one hash chain.
- **`gate.py` is three modules.** Wrapping a whole tool set (`protection.py`) and
  injecting a trusted argument (`binding.py`) are separate jobs with separate
  failure modes. Neither imports `Gate`; both take one.

### Fixed — the fifth adversarial pass

- **A projected record is always a mapping.** Handing one back unchanged when
  nothing had to be dropped let it sail past the canary scan and the secret
  detectors with `redactions: []`.
- **`rm -rf logs && mkdir logs` voided the erasure memory**, because the key was
  the parent directory's inode and a recreated directory is a new one.
- **The ReDoS split budget is spent by the pattern, not by each run of it.**
  Eight independent quadratic runs over disjoint alphabets were eight separate
  scores, all under the bound, while the engine's real work is their product.
- **A leaf is a leaf even when it carries attributes**, so projection no longer
  replaces `Money("12.30")` with its decoration.
- **`strict=True` on an audit sink means exactly `True`.** A `__getattr__`
  wrapper or a bare `Mock` answered truthy to every name, so "evidence outranks
  availability" was an opt-in nobody had to write.
- Plus every P1, P2 and P3 that pass found: the exception-chain walk descending
  into suppressed contexts, `InMemoryAuditSink.failed`, `$ref` siblings,
  `+json` media types, and the composed form body.

### Changed — the fifth pass

- **The package is eight subpackages** — `policy`, `decide`, `mediate`, `trail`,
  `importers`, `provenance`, `format`, `redos` — from 46 flat modules. Every
  public name keeps its import path.
- **A characterisation snapshot** of 6 804 decisions is checked into the suite as
  the tripwire every refactor since has had to leave unmoved.

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

### Changed — the first adversarial pass, before anything is published

This block carried a `## [0.1.0] - 2026-08-12` heading, and that release never
happened. The heading was written to satisfy a packaging gate that required a
dated entry for the version being built — evidence of a release demanded as the
precondition for making one — so the only way to pass it was to write the
evidence first. Three days later the file described a published artifact,
twenty-one README links pointed at a tag that did not exist, and two adversarial
passes were missing entirely. The gate asks the other way round now: a dated
entry must have a tag behind it.

Each item here is a change of behaviour rather than a bug fix. None of it is a
compatibility break for anyone, because nothing is on PyPI — which is exactly why
they land now rather than in 0.2.

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
