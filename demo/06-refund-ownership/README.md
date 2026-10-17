# 06 — refund row ownership

```
python attempts.py
```

Twelve attempts against one wrapped refund handler. Two of them should move money;
ten should not. The counter lives *inside* the handler, so what you read is a count
of side effects, not a count of decisions the library made about itself.

Exit code is the number of attempts that behaved unexpectedly. CI runs it.

## The setup

`ORD-123` belongs to `u1`, `ORD-789` belongs to `u2`, and both sit in the same tenant.
That is the point: tenant alone never separates them. The contract carries
`Constraint.owns("owner_id")`, and the owner comes back from `load_order` — the
trusted datastore — rather than from an argument the caller supplied.

## What the ten refusals cover

| attempt | rule |
|---|---|
| wrapped call on someone else's row | `resource_constraint` |
| `role="admin"` appended to the arguments | `arg_schema` |
| no principal bound | `no_principal` |
| role without the permission | `rbac` |
| live approval reused on another row | `resource_constraint` |
| host refuses confirmation | `requires_confirmation` |
| no confirmation callback wired | `requires_confirmation` |
| no resource resolver wired | `no_resource_resolver` |
| malformed order id | `arg_schema` |
| row absent from the datastore | `resolver_error` |

Three of those are wiring mistakes rather than attacks — no resolver, no confirm
callback, no principal. They are in the list because an integrator who forgets one
of them should get a refusal, not a refund.

The first line of output is the control: the same call against the unwrapped
handler, which runs once. Without it the zeros underneath prove nothing.

## Scope

Identity and rows come from the harness. No authentication, no database, no model,
no payment. This shows the boundary holding for these rules and this data; it is not
a test of an integration.
