# Histos — security model, guarantees, and honest limits

The gate's promise: *the model can be manipulated; the gate makes sure it still
can't do more than you allowed.* This document states what that guarantee rests
on — and, just as importantly, where it stops. Nothing here is sold as more than
it is.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately
to **lukasz.jakubowski1993@gmail.com** with enough detail to reproduce: the policy
(or a minimal version of it), the call that should have been refused, and what
actually happened. Expect an acknowledgement within a few days; this is a
small project, not a vendor with an SLA, and it is better to say so than to
promise a response time nobody is on call for.

**What counts as a vulnerability here:** any way to make the gate *allow* a call
its policy forbids, *leak* content its policy would redact, or *lose* an audit
record — without the attacker already controlling the host process. A bypass of a
limit that is documented below as a known residual (mechanical-only canary,
per-process limits and approvals, the resource TOCTOU window, shallow
nested-argument validation, a payload parked on an opaque object's attributes,
`mode="observe"` executing the call it denied) is not a new vulnerability — but a
*worse-than-documented* version of one is, and so is a case where the documentation
is simply wrong.

Supported for fixes: the latest released version, on the Python versions in
`pyproject.toml`. Nothing is backported.

## Trust model

- **Trusted:** the developer wiring the gates, and the `Principal` (role +
  attributes) the host binds **out-of-band**.
- **Untrusted:** external users and any content the agent reads (documents, tool
  outputs, retrieved data) — and, crucially, the **tool name and arguments** of
  every call, which a manipulated model constructs.
- **Out of scope (named, not hidden):** a malicious developer; a compromised
  dependency in the same process; **an agent that can reach the same resource
  without going through a wrapped tool** — see *"The agent must have no path around
  the tools"* below, which is the condition the rest of this document assumes.

**The gate is exactly as strong as the `Principal` bound to it, and the library
cannot check that binding** — a `Principal` built from a verified access token and
one built from a string the model produced are the same object by the time the gate
sees them. [`docs/identity.md`](docs/identity.md) is that condition written out in
full: where the line runs, what to read from Entra / Okta / Auth0 / Keycloak, why the
IdP's role names must not appear in a policy, and the five mistakes that all compile,
run, and leave you enforcing nothing.

## What holds (and on what condition)

### Resource authorization: only `source="resource"` binds to the *resource*
A constraint compares a **call argument** or a **resolved resource attribute**
against `principal.attributes` (trusted) or a literal — never an argument against
itself. The attacker supplies the argument but cannot change what the constraint
*requires*; they can only make it fail. But **which** thing you compare is
security-critical:

- `Constraint("tenant_id","eq",principal_attr="tenant_id", source="resource")` makes
  the `resource_resolver` look the **accessed** resource up in the datastore and
  compares its *real* owner to the principal. This is genuine resource authorization.
- `Constraint("tenant_id","eq",principal_attr="tenant_id")` (**`source="call"`**, the
  default) only checks that the caller-supplied `tenant_id` argument equals the
  principal's — **self-declaration, not ownership**. It protects nothing when the
  resource is keyed by a *different* argument: for `read_invoice(invoice_id, tenant_id)`
  a caller with tenant `acme` can pass `invoice_id=<an invoice owned by evilcorp>,
  tenant_id="acme"` — RBAC, schema and the `tenant_id=="acme"` check all pass, the tool
  keys on `invoice_id`, and it is a **cross-tenant read** (confused deputy / IDOR).
  `review_policy()` flags high-risk tools (write, or high/critical sensitivity) that
  rely on this `source="call"` form with no `source="resource"` constraint.

**It is only real under two conditions — both the developer's responsibility, and
the library cannot enforce either:**
1. **Identity is bound out-of-band.** The host sets `Principal` (role *and*
   `attributes`) from workload identity or an authenticated session — **never**
   from a tool argument or model output. The gate is exactly as strong as this.
2. **Resolvers fetch the real owner, not an argument.** For `source="resource"`
   constraints, the `resource_resolver` must look the resource up in the
   datastore and return its *actual* owner. A resolver that echoes an argument
   (`lambda t,a: {"tenant_id": a["tenant_id"]}`) re-creates the confused deputy.

**Residual:** row-level authorization is enforced **only where a constraint was
authored**. A tool with an RBAC grant but no constraint is authorized at the
*tool* level, not the *row* level — `get_record(id=victim)` passes because "this
role may call get_record" is true. `review_policy()` flags reachable **write**
tools with no resource constraint so this gap is loud, not silent.

### Confirmation is trusted and out-of-band — the agent cannot self-approve
Confirmation is a **host callback**, not a tool the agent can call, so approval is
not in the agent's action surface. With no callback the default is **fail-closed**.
But a naive `confirm=lambda req: True` (or one reading a field the agent controls)
defeats it — the same trap as identity.

The safe primitive is **`ApprovalStore`**: a trusted host (a human approver, a
secure console) calls `store.grant(request_fingerprint(tool, args, principal))`
**out-of-band**; the gate consumes it via `Gate(confirm=store.as_confirm())`.
Approvals are **single-use** and **bound to the exact (tool, args, principal)**, so
one cannot be replayed to a different action, and the agent — which cannot write to
the store — cannot approve itself. Confirmation must always originate outside the
model; never from a boolean the model can influence. Build the store **with the
policy** (`ApprovalStore(policy)`) if you rely on `confirmation.expires_in`: that is
where the declared window comes from, and a store built bare holds a grant until it is
consumed or revoked. The store is also per-process — see *"Limits and approvals are
per-process"*.

### Malformed / non-conforming output
Name-based field redaction cannot save a secret that lands in an **undeclared**
field. So set `strict_returns=True` on a tool and the post-gate enforces the
declared return schema:

- **conforming** → deterministic field-level redaction (sensitive fields hidden);
- **schema violation / unknown shape** → conservative, per `on_output_violation`:
  `"redact_all"` (default — replace the whole output) or `"deny"`;
- opt out per tool with `on_output_violation="allow"`.

Left at the default (`strict_returns=False`), the return schema is only a set of
redaction *hints* and undeclared fields pass through — a deliberate,
documented trade-off, flagged for write tools by `review_policy()`.

### A raising tool does not escape the post-gate
An exception is the *other* way a tool hands content back to the model, so it goes
through the POST chain as well: the error text is scanned for canary tokens and
recognised secrets under the same `output` settings that govern the return value.
When something is removed the gate raises **`ToolErrorRedacted`** carrying the
redacted text; when nothing is, the original exception is re-raised untouched, with
its traceback intact.

The original exception object is deliberately **not** attached as `__cause__` *or*
`__context__` — its `args` still hold the unredacted text, and anything that formats
an exception chain (a traceback printer, most log handlers) would put it straight
back on screen. `raise ... from None` alone only suppresses the *display*, so the
re-raise happens outside the handler.

**Residual, and it is the canary limit again:** matching is mechanical. The
exception path runs the same two-tier matching as the return path — verbatim plus a
fixed normalization — so a spaced-out or zero-width-padded token is caught. (Until an
audit found it, this path matched verbatim only, which made a raised message the
cheapest way out of the process: one zero-width space carried a canary to the model
inside an ordinary `ValueError`.) An error message that base64s, paraphrases or
translates the secret still passes, exactly as it would in a return value. Redaction also applies to
`str(exc)` — an exception whose `__str__` masks its own contents hides from the
check, and one that carries data on custom attributes rather than in its message is
not reached. Output projection, strict returns and sensitive-field redaction do
**not** apply here: all three key on a declared return shape, which an exception
does not have.

### A lazy return does not escape the post-gate either
Every output control — projection, canary redaction, sensitive-field redaction, secret
scanning — reads a **materialised** value. A tool that returns a generator, an iterator
(`map`, `filter`, `iter(rows)`, a file handle, a `csv` reader), a coroutine, an async
generator, or any other object the post chain can only walk *past* rather than into,
hands back a payload behind an iteration nothing performed. So the post-gate refuses
it: DENY, rule **`uninspectable_output`**, with a message telling the author to return
the collected result. The check walks the same containers the post chain walks — dict
keys and values, list, tuple, set, frozenset — so `{"rows": (r for r in hits)}`, the
most ordinary MCP result there is, is refused too, and so is a structure nested deeper
than that walk follows. The same check reads a raising tool's `exc.args`, because
`raise ToolError(rows_iterator)` hides a payload from `str(exc)` exactly as a lazy
return hides one from the post chain.

A *streaming tool* — one written with `yield` — is refused earlier, at wrap time. This
case cannot be: `def search(q): return (row for row in rows)` looks like an ordinary
function until it has run, and so does an async tool forced onto the sync path with
`is_async=False`. Until an audit found it, the post chain scanned the iterator *object*,
found no strings in it and recorded `allow` with `redactions: []` — a clean line in the
log underneath a canary, a secret and a projected-away field on their way to the model.

**The tool has already run when this fires.** That is the shape of the control and not
a defect in it: the denial stops the unscanned payload reaching the model, it cannot
undo the call, the row it wrote or the money it moved. Anything whose *side effect* must
be bounded has to be bounded in the PRE phase, by policy. What the gate can still do at
the return, it does: a refused generator or coroutine is closed rather than left to the
collector holding a cursor open, though an iterator found *inside* a refused structure
is not — it may be the tool's own long-lived handle sitting next to the rows.

**The cost of this one is paid by honest tools**, and it is worth naming: an iterable
that is not one of the containers above is refused even when it holds nothing secret —
a `deque`, a `dict.values()` view, a lazy result wrapper with an `__iter__`. The remedy
is one call (`list(...)`, `dict(...)`) and the refusal names it, but this lands at the
tool's first call rather than at deploy, on a tool that worked yesterday. It was
chosen over the alternative screen — "an object that says it is iterable is probably
fine" — because that one cannot tell a `deque` of rows from the wrapper an ORM hands
back one lazy page at a time, and being wrong in that direction is silent.

**Residual: an opaque object.** Detection reaches exactly as far as redaction does. A
generator parked on an *attribute* — `Page(rows=<generator>)`, a Pydantic model, any
custom class that does not advertise itself as iterable — is not seen, for the same
reason a canary in a dataclass field is not: the post chain does not read attributes,
and one that did would be executing arbitrary `@property` code inside a security check
(see [`docs/tech-debt.md`](docs/tech-debt.md) D7). A legacy `__getitem__`-only sequence
is likewise left alone, because every client object with subscript access defines one.
An object return is therefore inert to the whole output half of the gate — refusal
included — which is what `strict_returns=True` plus a declared `returns` shape exists
to rule out: an object does not match a declared field map, so `on_output_violation`
handles it instead of the traversal.

### Fail-closed
Any exception inside a check becomes DENY. No principal → DENY. A gated tool with
no argument schema → DENY. No individual check ever fails *open*: there is no
permissive default, no `on_missing`, and no toggle that turns a denial into a warning.

The **gate as a whole** does have a dry run — `mode="observe"`, below — and this
document used to claim "there is no fail-open mode in the gate", which is false in the
only reading a reader cares about: in observe mode a call the policy denies executes.
It is a mode you select for the gate, deliberately and once, not a state a failing
check can reach; but it is the thing that sentence denied existed, so the sentence is
gone.

## Where it stops (honest limits)

### The agent must have no path around the tools

This is the precondition the whole boundary rests on, and it is stated first because
it decides whether anything below matters.

Histos mediates a **wrapped tool call**. If the same agent also holds a shell, a code
interpreter, a general SQL client, an unrestricted HTTP client or raw filesystem
access, it can reach the same resource without passing a gated tool — and no argument
contract, ownership rule or output projection applies to the path it took instead.

The test is one question:

> **Can the agent execute code you did not write?**

*No* — a support, refund, CRM, scheduling or back-office agent whose entire reach is
a closed set of application tools. Here the boundary is complete: there is no lower
layer to slip through, which is also why `resource.owns` is genuine row
authorization rather than one of several places ownership might be checked.

*Yes* — a coding agent, an agent with a Python tool, one that can run arbitrary
queries. Here Histos is **defence in depth, not the perimeter**. The perimeter is
credentials, sandboxing, network egress control, filesystem scope and authorization
in the backend that owns the data. Publicly documented agent incidents that ended in
real compromise have mostly run through those layers — sandbox escape, credential
reuse, privilege escalation — rather than through a badly-argued call to a
well-defined business tool. A policy that bounds `make_refund` while the same agent
holds a shell is guarding a door in an open field.

Do not read this as "then it is worthless there". Narrowing what a compromised agent
can reach is worth doing at every layer. Read it as: **if you can only afford one
control and your agent can execute code, this is not the one to buy first.**

### `mode="observe"` executes the call it denies

The second thing that decides whether any of the above applies to your deployment,
after the question of whether the agent can go around the tools: which mode the gate is
in. Observe is a **whole-gate dry run**, and it is a deliberate feature, not a fallback
— the calibration step that lets a team point a policy at real traffic before a denial
can break somebody's workflow.

**What it does:** everything the enforcing gate does, up to the verdict. Same checks in
the same order, the same limit slot consumed by an allowed call and none by a denied
one, and the same audit record — carrying `effect=deny enforced=false executed=true`,
three fields that only appear together here. Reading them is the point: they are the
list of calls this policy would have refused, drawn from real traffic.

**What it does not do:** block a denied call, redact an output, withhold a canary or a
detected secret, or stop a call with **no principal bound at all** — every one of those
runs the tool and returns its result to the model untouched, including a lazy return,
which observe passes through unread rather than refuse (closing it would destroy the
very data the run exists to observe). An audit record is not a control. A gate left in
observe protects nothing; it measures.

What observe *does* do is reach the decision enforce would reach. The policy is
evaluated against the bound arguments in both modes — a run that judged the model's
`tenant_id` while enforce judges the principal's would predict denials enforce never
makes, and miss ones it does, which is the one job observe has. The call itself is
untouched: the tool receives exactly what it would have received with no gate at all,
`bind` included. An earlier version rewrote the arguments in observe too, and a dry run
whose side effects differ from the ungated app is measuring something else.

### The post-gate stops reading at 4 MiB of tool output

Every outbound control has to read the value to act on it, and reading is linear in the
size of the value while the tool that produced it is attacker-influenced. So there is a
budget — 4 MiB of joined text by default, `Gate(output_budget=...)` — and a result that
exceeds it is not partially scanned: scanning a prefix and reporting on the rest is the
fail-open the inbound budget refuses an input to avoid.

What happens instead is `deny` or drop-the-value, and `on_output_violation` chooses
between them: `deny` refuses the call outright, and everything else — including `allow`
— replaces the result with `[REDACTED: tool output exceeded the scan budget…]` and
records `output:redacted_all`. The tool has already run in both cases; neither undoes it.

There is deliberately **no** switch that returns an unscanned result. `allow` had that
meaning for one pre-release iteration and it was the wrong knob to hang it on:
`on_output_violation` is malformed-*shape* policy, hosts set `allow` because a vendor's
return drifts, and those hosts had thereby also switched off canary and secret redaction
for every oversized return — measured egressing a planted canary and an AWS key under an
ALLOW record.

A reporting tool that legitimately returns tens of megabytes needs the budget raised, and
raising it is the supported answer: `output_budget=` on `Gate`, `gate()` and `protect()`.
That enlarges what gets scanned. Leaving it at the default and hitting it is not a
detection: it is the gate saying it could not look.

The budget counts values as well as characters, because the passes it bounds walk and
rebuild the whole structure: a return of six million integers carries no text at all and
still costs seconds in the secret pass.

### Canary is a mechanical control + an oracle — NOT exfil prevention
The pre-gate DENYs a canary token in an argument and the post-gate REDACTs it from
output, **at runtime** (not test-only). Matching is two-tier on both sides: verbatim,
and again after a fixed closed normalization (NFKC, zero-width characters dropped, a
closed separator set dropped, case folded) — so `C A N A R Y-7f3a-SECRET`,
`CANARY_7f3a_SECRET` and a zero-width-padded token all match. The post-gate also joins
every str/bytes leaf of a return and re-checks that, so a token **split across several
output fields** is caught; because a split token cannot be located leaf by leaf, the
whole value is dropped rather than partially redacted. But matching is still
**mechanical**: base64, paraphrasing or translating the secret **passes**. Two further
reachability limits:
- **Opaque objects.** Redaction traverses str/bytes/dict(keys+values)/list/tuple/
  set/frozenset. A canary inside a dataclass/Pydantic attribute or any custom
  object's fields is **not** reached.
- **Masked stringification.** The pre-gate arg scan works on `str(value)`. An
  argument whose `__str__`/`repr` masks its contents (e.g. Pydantic `SecretStr`)
  hides a canary from the check.

So: treat canary as a deterministic guard against a mechanical leak and,
above all, as a **"prove it" oracle** — plant one, and if it ever surfaces, your
other controls (or a semantic tier, if one is wired) failed. Do not sell it as exfiltration
prevention.

### There is no run or session scope
`budget` counts calls per `(principal.identity, tool)` **for the life of the store**,
and `rate_limit` per rolling window on the same key. The key is `identity` **alone** —
not the role, not the attributes — so two callers sharing an identity share one
allowance, a caller whose identity changes gets a fresh one, and a `Principal` built
with no `identity` at all lands in a single shared `<anonymous>` bucket with every
other, where one tenant's traffic exhausts another's budget. [`docs/identity.md`](docs/identity.md)
says so at the point where the field is introduced. Neither limit has a notion of an
*agent run*. So "at most 20 refunds" means twenty for that identity until the process
restarts — not twenty per run, and not twenty across a fleet. A long-lived server
therefore exhausts a principal's budget permanently rather than per invocation,
which is correct for a worker or a single-run script and surprising anywhere else.

Bounding a whole run — *"at most N tool calls, or N steps, in this invocation"* —
needs a scope key the format does not yet have (`limit_scope` on the roadmap). Until
it does, the honest claim is per-call least privilege plus a per-identity ceiling,
not "the agent cannot loop".

### Limits and approvals are per-process
`check` + `consume` are **atomic within a process** (a lock closes the
check→consume race, so concurrent calls cannot both pass a `budget=1`). But the
counters live in memory: across processes/replicas, "max 5" becomes "5 per
instance", and injection fanned across processes exceeds the intended global cap.
A true global limit needs shared state (e.g. Redis) — opt-in infra, in tension
with zero-dependency. The stateless core (RBAC / schema / constraint / canary) is
unaffected.

`ApprovalStore` is in-memory on the same terms, and the consequence points the other
way — towards refusing, not allowing. A grant written by a trusted host into worker 3's
store does not exist in workers 1, 2 and 4, so on a multi-worker deployment the
approved retry only proceeds if it happens to land back on worker 3; anywhere else the
human approves again, or the call never completes. Nothing is *widened* by this — an
approval cannot be replayed into a process that never received it — but the
grant-then-retry flow described above assumes one process, and running four gunicorn
workers is enough to break it. Carrying an approval between processes needs the signed
protocol in [`docs/tech-debt.md`](docs/tech-debt.md) (D4); until then, route
confirmation-required tools through a single worker or a single-process service.

### Resource-state TOCTOU (check-time vs execute-time)
A `source="resource"` constraint reads the resource's state via the resolver **at
check time**. Between that check and the tool actually executing, the resource can
change (a record re-parented to another tenant, a permission revoked). The gate
cannot close this window — it is not the system of record. **Responsibility
boundary:** for anything where this matters, the *executing* system must be the
final authority — the tool should carry a **scoped credential/context** (so the
backend enforces the same tenant/owner at execution) or the backend must re-check.
The gate bounds *which* operations the agent may attempt; it does not replace
transactional authorization at the point of mutation (see the backend-authz note in
the trust model).

### Argument-pattern regexes are screened for ReDoS at load
Patterns are **compiled at load**, so an invalid regex fails loudly rather than
fail-closed on first call — and they are now also **screened**: a pattern whose
structure admits exponential backtracking (nested or adjacent unbounded quantifiers
over overlapping character sets, `(a+)+$` being the canonical one) is **refused at
policy-load time**, with a suggested rewrite. This matters because an imported MCP /
OpenAPI schema is written by whatever server the user pointed at, and stdlib `re` has
no execution bound; screening is what a zero-dependency core can do without swapping
in a non-stdlib engine.

The screen is structural and therefore conservative in one direction: it can refuse a
pattern that would in practice have been fine. It does not claim to catch every
pathological regex ever written — a polynomial (not exponential) blowup on a very long
input is still possible, which is why the length cap below is the second bound rather
than the only one. *(Array arguments are bounded twice: per element by the string
length cap, and in aggregate by a scan budget, so neither an oversized element nor an
unbounded element count can turn one schema-valid call into a stall.)*

### Argument validation is shallow for nested objects
The schema validator is deliberately tiny. A `type="object"` argument is
checked only for being a `dict` — its **inner fields are not validated**. Array
elements are type-checked, and for `item_type="string"` each element is bounded by
the same length/pattern caps as a scalar string, but there is no cross-field or
deep-structure validation. A tool that takes deeply nested arguments must not assume
the gate validated the inner structure; validate it in the tool, or keep arguments flat.

### Complete mediation depends on wrapping every tool
The gate can only mediate a tool that was **wrapped**. `Gate.declared_but_unwrapped()`
surfaces tools the policy declares but that were never wrapped — but a tool that is
**neither declared nor wrapped is invisible**: the agent can call the raw function
ungated and nothing flags it. The same applies to a *reference you kept*:
`protect_tools()` returns new objects and leaves the originals alive, so a missing
reassignment loses enforcement entirely and silently. Ensuring every tool the agent can reach flows through
the gate is the host/adapter's responsibility (the framework adapter is the
chokepoint); the library cannot guarantee it for a function it was never handed.

### Audit tamper-evidence depends on a key, and truncation detection on a sidecar
`JSONLAuditSink(hash_chain=True)` **unkeyed** detects reordering and naive
single-record edits — but an attacker with write access can rewrite a record and
recompute every downstream sha256, and `verify()` then passes. For tamper-evidence
against a motivated writer, pass `key=<secret>` (kept off the box): the chain becomes
HMAC-SHA256 and rewriting requires the secret.

**Truncation is a separate problem and needs the sidecar.** A hash chain alone cannot
tell a log that was cut short from a log that is merely young — every record in both
still verifies. The sink therefore writes a `<log>.tip` file beside the log recording
where the chain has reached; `verify()` compares them and reports a truncated tail.
Delete the sidecar and that detection is gone, in keyed and unkeyed mode alike. This
document previously claimed the unkeyed chain detected truncation on its own; it did
not, and an audit caught it.

Deleting the log *and* the sidecar together leaves nothing on disk to contradict a
fresh chain, and a running process is the only thing left that remembers. A sink that
finds its log shorter than it left it therefore writes the break into the file rather
than starting over, so `verify` reports it. **Ordinary log rotation reads as exactly
that**, and deliberately: `rm` and `mv` both leave a fresh inode at the same path, so
nothing inside the process can separate erasure from rotation. A rotated log reporting
a broken chain costs an operator an explanation they already have; a missed erasure
costs the evidence. After rotating, call `sink.rotated()` — or point a new sink at the
new path, which has no history — and the next chain starts clean. It is an explicit
call rather than something inferred from the file, because every on-disk signal that
would distinguish rotation from erasure is one an attacker can produce too; a call from
inside the process that owns the sink is not. Across a restart there is no memory at
all — ship the tip somewhere the host cannot write if that matters.

**Concurrency.** `JSONLAuditSink.record` is atomic within a process (a `threading.Lock`)
and, on POSIX, across processes (`flock` on the log). On Windows there is no
cross-process guarantee: point separate processes at separate logs. Before this was
fixed, ordinary concurrent writes corrupted the chain and `verify()` then reported
tampering on a log nobody had touched — the failure mode that teaches people to ignore
the signal.

## What `review_policy()` surfaces (turning silent gaps loud)

- write tools with **no resource constraint** (row-level authz not enforced);
- **permissive** argument schemas (`allow_extra`, e.g. inferred from `**kwargs`)
  where deny-by-default on arguments is off;
- tools with **no argument schema** (fail-closed) and **no return schema**
  (post-gate can't redact);
- **unreachable** tools and grants to **unknown** tools/roles.
