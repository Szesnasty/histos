# Known debt

Deliberate shortcuts, in the open. Same principle as
[`../SECURITY.md`](../SECURITY.md): state the limit rather than hide it. Each entry
says what it is, why it is tolerated, and what resolves it.

---

## D1 — The LangChain adapter is tested against a fake, not the live object

[`integrations/base.py`](../src/histos/integrations/base.py) is framework-free
and fully tested. [`integrations/langchain.py`](../src/histos/integrations/langchain.py)
— the part that reconstructs a `StructuredTool` and preserves `name` /
`description` / `args_schema` — has six tests, against a `_FakeStructuredTool` and a
fixture that flips `_HAVE_LANGCHAIN`. They pin both defects this adapter has had: an
async-only tool resolving to LangChain's own `_run` dispatcher, and `return_direct`,
`metadata` and `tags` being dropped on protect. This paragraph said the module was
`# pragma: no cover` and it has not been for some time.

**The cost, stated accurately:** what is untested is the *live* object, not the logic.
A change to LangChain's tool API would break the real adapter and not the fake, so the
six tests would stay green. That is a narrower gap than "unverified" and it is the one
that remains.

**Partly answered since.** `demo/00-mediation` drives thirteen entry points at a
gated tool — every public and private LangChain path, both async paths, the
attributes on the object, the guard's own closure, and a compiled LangGraph
`ToolNode` — and found one real bypass, now closed (see the resolved list). It runs
outside this suite because it needs a framework installed. What remains unverified
is the *loop*: that an agent survives a denial and carries on usefully.

**What resolves it:** langchain-core in the dev extra plus one integration test per
adapter, in a CI job allowed dependencies the library itself refuses.

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

**Two of the four have since landed, and this paragraph claimed otherwise.** An
approval no longer survives a policy change: the ruleset in force is recorded at grant
and compared at consume, so a deploy between the click and the call refuses it rather
than spending it. `confirmation.expires_in` is enforced too — by the store, which has
the clock the engine deliberately does not. Passing the paused `GateRequest` pins both
values from the exact snapshot that requested approval, so a store may safely survive a
Gate hot reload; the fingerprint-only compatibility form cannot carry that evidence.

**The cost that remains:** no nonce and no approver identity in the tuple, and the
store is in-process, so an approval cannot be carried between processes and the record
says *that* someone approved rather than *who*.

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

## D7 — The post-gate cannot see inside `__slots__` or a `@property`

**Narrowed since this was written, and this entry said otherwise for two passes.** It
claimed a dataclass, a Pydantic model "or any other opaque object" is walked around,
never into. Four of those shapes are entered now — a dataclass, a NamedTuple, anything
keeping its state in an instance `__dict__` (Pydantic v1 and v2 and every ordinary
class), and an attribute hung on a `str`/`int`/`bytes` subclass — by the fifth and
sixth adversarial passes respectively. A canary on any of them is found and the value
is dropped whole.

What remains is narrower and is the part that cannot simply be widened: state that
lives only in **`__slots__`**, a value behind a **`@property`**, and a C extension type
keeping its state where no Python attribute shows it. The same residual, in the same
words, is in [`../SECURITY.md`](../SECURITY.md) — and the two documents disagreeing
about it is what this rewrite fixes. `tests/test_invariants.py` pins the matrix and
names both files in its failure message, so the next change to the reach has to move
all three together.

**Why tolerated:** a `@property` is author code, and running it inside a security check
can raise, can be expensive, and can return something different on the second read than
the redactor inspected on the first — a TOCTOU inside the redactor. Slots cannot be told
apart from a stdlib value type's internals, so reading them would project a `UUID` into
`{"int": …, "is_safe": …}` and destroy the value. Reading an instance `__dict__`, which
is what the passes above do, runs no user code — which is why that half could be widened
and this half cannot.

**What mitigates it:** `strict_returns=True` with a declared `returns` shape. An object
return does not match a declared field map, so it is handled by `on_output_violation`
— `redact_all` by default, which replaces the whole value. That is a blunt answer, but
it means the unscanned case is reachable only with strict returns off.

**What resolves it:** a declared way to materialise an object return — `returns`
already names the fields, so a mapping seam (`asdict`, a `to_dict` hook the contract
points at) would let the existing chain run over it — or making an undeclared object
return refusable by default. Demand-pulled: nobody has asked yet, and the mitigation
above is one policy flag away.

---

## Resolved — kept for the trail

- **CI did not drive the real framework executors.** It now installs
  `langchain-core` and `langgraph` and runs `demo/00-mediation/hunt.py` on every push:
  public, private and async paths plus a compiled LangGraph `ToolNode`. The remaining
  agent-loop denial recovery gap is D1 rather than a separate debt.

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
- **The adapter published a pointer around itself.** `guard_callable` used
  `@functools.wraps(fn)`, which sets `__wrapped__` to the *ungated* function — so a
  gated LangChain tool carried `tool.func.__wrapped__`, and calling it executed the
  tool with no gate decision at all. A mediation hunt (`demo/00-mediation`) found it
  by trying thirteen entry points and watching which ones moved the money. Worse,
  `_unwrap_target` in this library follows `__wrapped__` chains, so re-wrapping an
  already-guarded callable would have silently stripped the guard. Closed by pinning
  `__signature__` explicitly — frameworks still get the name, doc and parameters they
  read — and removing the pointer, with two regression tests that need no framework.
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
