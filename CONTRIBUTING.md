# Contributing

Thanks for looking at this. `histos` is a **security** library, so the bar for
a change is a little different from a normal package: the useful contribution is
usually a *test that proves the gate is weaker than it claims*, not a new feature.

## Setup

```bash
python3.12 -m venv .venv          # 3.12 or newer
.venv/bin/pip install -e ".[dev]"
```

## The two commands

```bash
.venv/bin/python -m pytest        # the whole suite; it runs in well under a second
.venv/bin/python -m ruff check .  # lint + import order
.venv/bin/python -m ruff format . # only if you want it; the repo is not auto-formatted
```

Both must pass before a change lands. The suite is deliberately fast — if it ever
stops being instant, that is a bug worth reporting.

## Invariants a change must not break

These are the properties the library is *for*. A pull request that trades one of
them for convenience will be declined even if every test passes:

1. **Fail-closed.** Any exception inside a check becomes `DENY`. There is no
   fail-open mode and no "log and continue" path.
2. **Deny-by-default.** An unknown tool, a tool with no argument schema, an
   argument not named in the schema, and a call with no bound principal are all
   refused. New surfaces inherit this default, not the opposite.
3. **Identity is bound out-of-band.** The `Principal` comes from workload identity
   or an authenticated session — never from a tool argument, a model output, or
   anything reachable from the agent's action surface. Same rule for approvals.
4. **The request-only invariant.** A decision may read the tool name, the
   arguments, the trusted principal, and the static policy. Never conversation
   history, retrieved documents, or prior tool outputs.
5. **Two audiences.** Rich detail (`rule / field / expected / received`) goes to
   the developer and the audit sink. The model gets `public_reason` and nothing
   tunable — no thresholds, no allowlist entries, no tenant names.
6. **Zero runtime dependencies.** The enforcement core is stdlib-only. Anything
   else goes behind an optional extra (as YAML does), and the core must keep
   working without it.
7. **Deterministic.** No models, no heuristics in the core. Heuristic pattern
   matching lives in `content_rules` — opt-in, off by default, and documented as
   what it is. Semantic judgement belongs in a separate tier, not here.

## Honesty about limits is a feature

[`SECURITY.md`](SECURITY.md) exists to say where the guarantee stops: canary is
verbatim-only, limits are per-process, resource checks have a TOCTOU window,
nested arguments are shallow-validated, and complete mediation depends on every
tool actually being wrapped. If your change narrows one of those gaps, update that
section. If it introduces a new one, **document it in the same commit** — an
undocumented residual is worse than a known one.

## Adding a check to the PRE/POST chain

- The check lives in `engine.py`, in the documented order, and returns a
  `GateDecision` with a stable machine-readable `rule` slug.
- Add the slug to `_REMEDY` in `contracts.py` so a developer gets a "how to fix it"
  hint — and make sure the slug maps to a non-coaching `public_reason`.
- If the check is configurable, the setting belongs on `ToolContract` **and** in
  the bundle round-trip (`bundle.py`: both `_tool_from_dict` and `dump_bundle`) —
  a setting that loads but does not dump silently disappears on export.
- Anything that affects the policy structure must be reflected in
  `Policy.fingerprint()`, or two materially different policies will share a
  `content_hash`.
- Add a test for the allow path, the deny path, and the fail-closed path.

## Reporting a vulnerability

Do not open a public issue. See the reporting section at the top of
[`SECURITY.md`](SECURITY.md).
