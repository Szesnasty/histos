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
limit that is documented below as a known residual (verbatim-only canary,
per-process limits, the resource TOCTOU window, shallow nested-argument
validation) is not a new vulnerability — but a *worse-than-documented* version of
one is, and so is a case where the documentation is simply wrong.

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
model; never from a boolean the model can influence.

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

**Residual, and it is the canary limit again:** matching is verbatim and
structural. An error message that base64s, paraphrases or reformats the secret
passes, exactly as it would in a return value. Redaction also applies to
`str(exc)` — an exception whose `__str__` masks its own contents hides from the
check, and one that carries data on custom attributes rather than in its message is
not reached. Output projection, strict returns and sensitive-field redaction do
**not** apply here: all three key on a declared return shape, which an exception
does not have.

### Fail-closed
Any exception inside a check becomes DENY. No principal → DENY. A gated tool with
no argument schema → DENY. There is no fail-open mode in the gate.

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

### Canary is a verbatim, structural control + an oracle — NOT exfil prevention
The pre-gate DENYs a canary token in an argument and the post-gate REDACTs it from
output, **at runtime** (not test-only). But matching is **verbatim**: base64,
spelling it out, or translating the secret **passes**. Two further reachability
limits:
- **Opaque objects.** Redaction traverses str/bytes/dict(keys+values)/list/tuple/
  set/frozenset. A canary inside a dataclass/Pydantic attribute or any custom
  object's fields is **not** reached.
- **Masked stringification.** The pre-gate arg scan works on `str(value)`. An
  argument whose `__str__`/`repr` masks its contents (e.g. Pydantic `SecretStr`)
  hides a canary from the check.

So: treat canary as a deterministic guard against the *dumbest* verbatim leak and,
above all, as a **"prove it" oracle** — plant one, and if it ever surfaces, your
other controls (or a semantic tier, if one is wired) failed. Do not sell it as exfiltration
prevention.

### There is no run or session scope
`budget` counts calls per `(principal, tool)` **for the life of the store**, and
`rate_limit` per rolling window on the same key. Neither has a notion of an *agent
run*. So "at most 20 refunds" means twenty for that identity until the process
restarts — not twenty per run, and not twenty across a fleet. A long-lived server
therefore exhausts a principal's budget permanently rather than per invocation,
which is correct for a worker or a single-run script and surprising anywhere else.

Bounding a whole run — *"at most N tool calls, or N steps, in this invocation"* —
needs a scope key the format does not yet have (`limit_scope` on the roadmap). Until
it does, the honest claim is per-call least privilege plus a per-identity ceiling,
not "the agent cannot loop".

### Limits are per-process
`check` + `consume` are **atomic within a process** (a lock closes the
check→consume race, so concurrent calls cannot both pass a `budget=1`). But the
counters live in memory: across processes/replicas, "max 5" becomes "5 per
instance", and injection fanned across processes exceeds the intended global cap.
A true global limit needs shared state (e.g. Redis) — opt-in infra, in tension
with zero-dependency. The stateless core (RBAC / schema / constraint / canary) is
unaffected.

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

### Argument-pattern regexes can ReDoS if imported from untrusted schemas
Patterns are **compiled at load** so an invalid regex fails loudly (not
fail-closed on first call). But stdlib `re` has **no execution bound**: a
catastrophic-backtracking pattern (`(a+)+$`) imported from a third-party MCP /
OpenAPI schema can stall the calling thread on a crafted argument. Treat imported
patterns as untrusted; keep patterns simple. Full ReDoS immunity would need a
non-stdlib regex engine (out of scope for a zero-dependency core). *(String array
elements are bounded by the same length cap per element, so an oversized element
cannot slip past this bound.)*

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
ungated and nothing flags it. Ensuring every tool the agent can reach flows through
the gate is the host/adapter's responsibility (the framework adapter is the
chokepoint); the library cannot guarantee it for a function it was never handed.

### Audit tamper-evidence depends on a key
`JSONLAuditSink(hash_chain=True)` **unkeyed** detects truncation, reordering and
naive single-record edits — but an attacker with write access can rewrite a
record and recompute every downstream sha256, and `verify()` then passes. For
tamper-evidence against a motivated writer, pass `key=<secret>` (kept off the
box): the chain becomes HMAC-SHA256 and rewriting requires the secret.

## What `review_policy()` surfaces (turning silent gaps loud)

- write tools with **no resource constraint** (row-level authz not enforced);
- **permissive** argument schemas (`allow_extra`, e.g. inferred from `**kwargs`)
  where deny-by-default on arguments is off;
- tools with **no argument schema** (fail-closed) and **no return schema**
  (post-gate can't redact);
- **unreachable** tools and grants to **unknown** tools/roles.
