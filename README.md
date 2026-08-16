# Histos

> ## Hijacked. Still bounded.

**Deterministic authorization for AI agent tool calls — before execution and after
return.** The model proposes. Your policy decides.

Histos puts an in-process security boundary around the tools an agent can call. It
does not guess whether a prompt is malicious. It enforces one narrow loop even when
the model is manipulated:

1. **Authorize the input** — tool, arguments, principal and trusted resource facts.
2. **Execute only within policy** — or deny / require confirmation before side effects.
3. **Constrain the output** — project and redact before it returns to the model.

No proxy, model or service is required. The core has zero runtime dependencies,
works with sync and async tools, and keeps ordinary policy evaluation in-process.
It is deliberately a small Python enforcement layer, not an identity platform,
sandbox or fleet-governance suite. Audit, coverage, tool import and drift detection
make that boundary reviewable and deployable.

## Why this exists

A stronger prompt can reduce the chance of a bad decision. It cannot authorize a
payment, prove tenant ownership or prevent a forbidden tool call from executing.
Histos treats model input, retrieved documents and tool output as untrusted, then
checks the action against policy written before the agent encountered them.

```text
model / conversation / retrieved content / tool output   untrusted, variable
────────────────────────────────────────────────────────────────────────────
policy + authenticated principal + trusted resource data trusted boundary
```

This is enforcement, not prompt-injection detection. Detection asks whether content
looks dangerous; Histos asks what the agent is allowed to do regardless. Its schema,
RBAC, resource and binding checks are deterministic for their inputs; resource
lookups, stateful limits, clocks and human approval remain runtime inputs.

## See the boundary hold

The repository contains five runnable demos: a LangChain clinic receptionist, a
LangGraph accounts-payable workflow, a framework-free on-call agent, an MCP tool
rug pull, and a mediation harness. Each attack is judged from actual datastore
effects, not from what the assistant claimed it did.

| scenario | without Histos | with a complete policy |
|---|---|---|
| poisoned clinic note redirects an SMS | patient data sent off-site | recipient rebound to the authenticated patient |
| invoice quietly swaps the supplier IBAN | 14,200 PLN sent to the wrong account | payee denied against trusted supplier data |
| injected runbook requests zero replicas and a production deploy | service damaged and an invented version deployed | arguments and resource state keep production unchanged |
| MCP vendor rewrites a tool description after review | ordinary schema diff is silent | description drift makes the CI command exit 1 |

In the controlled `qwen2.5:7b` runs, 6 of 11 attacks damaged the competent baseline
and 0 of 11 damaged the fully mediated version. Those model-driven figures were
measured manually at temperature 0; they are evidence from these scenarios, not a
general benchmark. A larger model avoided some baseline attacks, while the policy
bounds remained deterministic. The clinic policy also demonstrates a real product
cost: binding the SMS recipient removes caller-selected delivery. The full methods,
raw distinctions and partial-wiring failure are documented in the
[demo report](https://github.com/Szesnasty/histos/blob/main/demo/README.md).

## Install

```bash
pip install "histos[yaml]"
```

Requires Python 3.12 or newer. The `yaml` extra adds PyYAML; JSON policies use only
the standard library. To see a hijacked call remain bounded with no model or
infrastructure, clone the repository and run `python examples/makeRefund_demo.py`.
The adversarial applications are in
[`demo/`](https://github.com/Szesnasty/histos/tree/main/demo).

## Protect a tool

```python
from histos import Field, GateDenied, Policy, Principal, Schema, ToolContract
from histos import gate, use_principal

def delete_user(user_id: int):
    return {"deleted": user_id}

policy = Policy(
    tools={"delete_user": ToolContract(
        name="delete_user",
        args=Schema({"user_id": Field(type="integer")}),
        access="write",
    )},
    permissions={"admin": frozenset({"delete_user"})},
)

safe_delete = gate(delete_user, policy=policy)

with use_principal(Principal(role="admin", identity="svc-1")):
    safe_delete(user_id=42)  # allowed

with use_principal(Principal(role="viewer", identity="svc-2")):
    try:
        safe_delete(user_id=42)
    except GateDenied as exc:
        print(exc.decision.rule)  # rbac
```

Set the `Principal` in trusted host code from an authenticated session or workload
identity — never from model output or a tool argument. `protect()` handles a whole
tool set and reports policy review and coverage; a supplied tool with no contract or
grant is still wrapped and denies by default. See the
[complete quickstart](https://github.com/Szesnasty/histos/blob/main/examples/quickstart.py)
and [commented policy](https://github.com/Szesnasty/histos/blob/main/examples/security.policy.yaml).

## A production adoption path

Import tool shapes from MCP, OpenAI tools, OpenAPI, JSON Schema or Python signatures.
Author what those schemas cannot know — roles, ownership, trusted bindings,
confirmation and output rules. Run `histos review` and `histos coverage`, calibrate in
`mode="observe"`, then enforce with a durable audit sink and drift check in CI.

Worked policies for RAG, refunds, outbound email, MCP and deployments live in the
[policy gallery](https://github.com/Szesnasty/histos/tree/main/policies).

## Read this before production

Histos is defense in depth, not a sandbox and not a replacement for backend
authorization.

- Every execution path must receive the wrapped callable. A raw tool retained or
  registered elsewhere is a bypass; coverage sees only the surface you declare.
- Principal, resource facts, confirmation and policy are trusted host inputs. Histos
  does not replace backend authorization, sandbox compromised code or undo side
  effects before a post-call check.
- Histos does not understand intent or stop unsafe workflows composed from separately
  allowed calls. Limits and built-in approvals are process-local; the default audit
  sink is memory-only.
- The complete joined argument text is limited to 1 MiB by default and can be raised
  with `input_budget=`. A field using `pattern` is limited to 4,096 characters because
  it runs through Python's backtracking regex engine; unpatterned text is not.

The exact guarantee, residual object-inspection limits and safe deployment patterns
are in [SECURITY.md](https://github.com/Szesnasty/histos/blob/main/SECURITY.md).

## Status and documentation

Histos 0.1.0 is an alpha API implementing Histos Policy Format Draft 0.1. The Python
engine, policy format, CLI, conformance corpus, LangChain/LangGraph adapters and tool
definition import/drift workflow exist today. A hosted control plane, JavaScript
runtime and dedicated MCP enforcement product do not.

- [Documentation map](https://github.com/Szesnasty/histos/tree/main/docs)
- [Policy reference](https://github.com/Szesnasty/histos/blob/main/docs/policy-reference.md)
- [Roadmap](https://github.com/Szesnasty/histos/blob/main/docs/roadmap.md)
- [Changelog](https://github.com/Szesnasty/histos/blob/main/CHANGELOG.md)

Apache-2.0.
