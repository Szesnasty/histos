# Histos conformance corpus

Language-neutral fixtures that define what "the same policy behaves the same way"
means. Every implementation — the Python reference engine, a future TypeScript one,
an MCP adapter, anybody's fork — must pass all three corpora to call itself Histos
compatible. What "passing" means precisely, and which fixtures are in scope for a
given release, is pinned by [`manifest.json`](manifest.json) rather than by this
prose.

Two properties keep this from rotting into a description of what one engine used to
do:

1. **The reference engine runs these as part of its own test suite**
   (`tests/test_conformance.py`). A change to Python that breaks the contract fails
   the reference engine's own suite that day, not the TypeScript port eighteen months
   later. *(Automating that suite is [known debt D2](../docs/tech-debt.md) — today it
   runs when someone runs it.)*
2. **Canonicalization is covered, not just decisions.** Implementations rarely
   diverge on `arg_schema`; they diverge on whether `1.0` and `1` hash the same, and
   then approvals bound to a policy hash silently stop matching across services.

## The three corpora

| directory | question | fixture shape |
|---|---|---|
| `decisions/` | given this policy, principal, resource and call — what is the verdict? | `policy`, `principal`, `resource`, `call` → `expect.effect` + `expect.rule` |
| `canonicalization/` | do these spellings of one policy mean the same thing? | `documents[]` (YAML and/or JSON) → one identical `content_hash` |
| `invalid-policy/` | which policies must be refused, and under which code? | `document` → `expect.code` from the POLICY namespace |
| `projection/` | how does a tool definition become a contract, and what are its lock hashes? | `kind` + `source` → `expect.contract` + the three `*_sha256` |

Fixtures are JSON so no implementation needs a YAML parser to run the suite —
except the canonicalization corpus, which needs one *by definition* (that is the
point of the YAML-vs-JSON cases).

## What "passes" means

Two levels, defined in [`manifest.json`](manifest.json). The split follows a real
dependency: every fixture is JSON *except* the canonicalization corpus, which needs a
YAML parser by definition.

| level | corpora | what it means |
|---|---|---|
| `core` | `decisions` + `invalid-policy` + `projection` | the same verdicts, the same refusals, and the same contract out of the same tool definition. A milestone for a port in progress — **not** a compatibility claim |
| `portable` | `core` + `canonicalization` | the above **plus** agreement on `content_hash`. The only level that may be called *Histos compatible* |

`projection/` sits in `core` because every fixture is JSON and because a drift check
is a *comparison*: an implementation that imports `minLength` differently reports
drift the reference engine does not, and a signal that fires in one runtime and not
another is worse than no signal. See
[`spec/json-schema-projection-0.1.md`](../spec/json-schema-projection-0.1.md).

The gap between them is the one that hurts silently: two engines can agree on every
verdict and still hash the same policy differently, at which point approvals bound to
a policy hash stop matching between services and nothing looks broken.

The manifest also writes down the rules that prose keeps losing — a skipped case is a
failure, not a partial pass; fixtures are pinned by `sha256`, so a modified corpus is
a different corpus; a claim names the `corpus_version` it ran against; and an engine
that **refuses more** than these fixtures expect has diverged, not hardened.

## Vocabulary

Decision codes and their meanings live in [`../spec/decision-codes.json`](../spec/decision-codes.json),
split into namespaces: **RUNTIME** (a `GateDecision.rule`), **POLICY** (a
`PolicyError.code`, raised at load time) and **REVIEW** (advisory findings, not yet
coded). Conformance asserts the *internal* code, not the agent-facing
`public_reason` — two engines that both say `ACTION_NOT_AUTHORIZED` for different
reasons are not compatible, they are merely equally quiet.
