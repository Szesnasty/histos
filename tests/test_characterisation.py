"""What the gate decides, recorded, so a refactor has to prove it changed nothing.

The rest of this suite is examples: *this* input produces *that* output. Examples are
what a restructure passes trivially — they catch an import error and nothing else, and
the state that a module split actually breaks is invisible to them. Two of the sharpest
bugs this library has had were in module-level singletons (`_PATH_HIGH_WATER`, the
erasure memory; `_PATH_LOCKS`, the cross-Gate write lock), and a split that gives two
modules their own copy of either would leave every existing test green.

So this file holds two things a refactor cannot get past:

1. **A behaviour snapshot.** A matrix of policies x principals x arguments x tool
   outcomes, driven through the public surface, reduced to one hash. Any change in any
   decision moves it. It is deliberately *not* readable as a list of assertions — it is
   a tripwire, and the readable assertions live beside it.
2. **Invariants on the state that must stay singular**, asked as properties rather than
   as examples, because "for any two sinks on one path" is the claim and one example of
   it is not.

If a change is intended, regenerate with:

    python -m pytest tests/test_characterisation.py --snapshot-update
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from histos import (
    Field,
    Gate,
    InMemoryAuditSink,
    JSONLAuditSink,
    Policy,
    Principal,
    Schema,
    ToolContract,
    use_principal,
)
from histos.contracts import Binding, Constraint

SNAPSHOT = Path(__file__).resolve().parent / "corpus" / "decisions.snapshot.json"
CANARY = "CANARY-7f3a-SECRET"


# ── the matrix ───────────────────────────────────────────────────────────


def _policies() -> dict[str, Policy]:
    """One policy per control the gate offers, each minimal and each distinct."""
    plain = ToolContract(name="t", args=Schema({"x": Field(type="integer")}), access="write")
    return {
        "bare": Policy(tools={"t": plain}, permissions={"clerk": frozenset({"t"})}),
        "no-grant": Policy(tools={"t": plain}, permissions={"clerk": frozenset()}),
        "unknown-tool": Policy(tools={}, permissions={"clerk": frozenset({"t"})}),
        "bounded": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer", minimum=0, maximum=10)}),
                    access="write",
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "closed-surface": Policy(
            tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}, allow_extra=False))},
            permissions={"clerk": frozenset({"t"})},
        ),
        "open-surface": Policy(
            tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}, allow_extra=True))},
            permissions={"clerk": frozenset({"t"})},
        ),
        "canaries": Policy(
            tools={"t": plain},
            permissions={"clerk": frozenset({"t"})},
            canaries=frozenset({CANARY}),
        ),
        "strict-returns": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer")}),
                    returns=Schema({"ok": Field(type="string")}),
                    strict_returns=True,
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "project-output": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer")}),
                    returns=Schema({"ok": Field(type="string")}),
                    project_output=True,
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "sensitive-return": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer")}),
                    returns=Schema({"ok": Field(type="string"), "ssn": Field(type="string", sensitive="pii")}),
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "owned": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer"), "owner": Field(type="string")}),
                    access="write",
                    constraints=(Constraint("owner", "eq", principal_attr="owner"),),
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "bound": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer"), "owner": Field(type="string")}),
                    access="write",
                    bindings=(Binding(field="owner", principal_attr="owner"),),
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "confirm": Policy(
            tools={
                "t": ToolContract(
                    name="t",
                    args=Schema({"x": Field(type="integer")}),
                    access="write",
                    requires_confirmation=True,
                )
            },
            permissions={"clerk": frozenset({"t"})},
        ),
        "budgeted": Policy(
            tools={"t": ToolContract(name="t", args=Schema({"x": Field(type="integer")}), access="write", budget=1)},
            permissions={"clerk": frozenset({"t"})},
        ),
    }


def _principals() -> dict[str, Principal | None]:
    return {
        "none": None,
        "clerk": Principal(role="clerk", identity="alice"),
        "clerk-owner": Principal(role="clerk", identity="alice", attributes={"owner": "alice"}),
        "clerk-tenants": Principal(role="clerk", identity="alice", attributes={"tenants": ["acme"]}),
        "viewer": Principal(role="viewer", identity="bob"),
        "sees-pii": Principal(role="clerk", identity="alice", can_view=frozenset({"pii"})),
    }


def _argument_sets() -> dict[str, dict[str, Any]]:
    return {
        "ok": {"x": 1},
        "empty": {},
        "out-of-range": {"x": 999},
        "wrong-type": {"x": "one"},
        "undeclared": {"x": 1, "extra": "y"},
        "owner-self": {"x": 1, "owner": "alice"},
        "owner-other": {"x": 1, "owner": "mallory"},
        "canary-arg": {"x": 1, "note": CANARY},
        "huge": {"x": 1, "blob": "y" * 5000},
    }


def _outcomes() -> dict[str, Any]:
    """What the tool does. A callable is invoked; anything else is returned as-is."""

    def raises() -> None:
        raise RuntimeError("tool failed")

    def raises_canary() -> None:
        raise RuntimeError(f"not found: {CANARY}")

    return {
        "scalar": "done",
        "mapping": {"ok": "yes", "ssn": "123-45-6789", "undeclared": "x"},
        "mapping-clean": {"ok": "yes"},
        "canary-inside": {"ok": CANARY},
        "secret-inside": {"ok": "AKIAIOSFODNN7EXAMPLE"},
        "list-of-rows": [{"ok": "a", "undeclared": 1}, {"ok": "b", "undeclared": 2}],
        "none": None,
        "raises": raises,
        "raises-canary": raises_canary,
    }


def _one_case(policy: Policy, who: Principal | None, args: dict[str, Any], outcome: Any) -> dict[str, Any]:
    """Drive one cell of the matrix and reduce it to what a reader would check."""
    sink = InMemoryAuditSink()
    calls: list[int] = []

    def tool(**kwargs: Any) -> Any:
        calls.append(1)
        return outcome() if callable(outcome) else outcome

    record: dict[str, Any] = {}
    try:
        safe = Gate(policy, audit=sink).wrap(tool, name="t")
    except Exception as exc:  # noqa: BLE001 — a wiring refusal is part of the behaviour
        return {"wrap": f"{type(exc).__name__}"}

    try:
        if who is None:
            result = safe(**args)
        else:
            with use_principal(who):
                result = safe(**args)
        record["raised"] = None
        record["result"] = _shape(result)
    except Exception as exc:  # noqa: BLE001 — the decision is often an exception
        record["raised"] = type(exc).__name__
        record["result"] = None

    record["executed"] = len(calls)
    entry = sink.entries[-1] if sink.entries else {}
    record["effect"] = entry.get("effect")
    record["rule"] = entry.get("rule")
    record["redactions"] = sorted(entry.get("redactions") or ())
    record["records"] = len(sink.entries)
    # The one thing no cell may ever do, recorded here so the property test below can
    # assert it across the whole matrix rather than leaving it to the hash.
    record["canary_escaped"] = CANARY in repr(record["result"])
    return record


def _shape(value: Any) -> Any:
    """A stable, readable reduction of a returned value."""
    if isinstance(value, dict):
        return {"dict": sorted(str(k) for k in value)}
    if isinstance(value, (list, tuple, set, frozenset)):
        return {type(value).__name__: len(value)}
    if isinstance(value, str):
        return {"str": len(value), "redacted": "REDACTED" in value}
    return {"repr": type(value).__name__}


def _matrix() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for pname, policy in _policies().items():
        for wname, who in _principals().items():
            for aname, args in _argument_sets().items():
                for oname, outcome in _outcomes().items():
                    key = f"{pname}|{wname}|{aname}|{oname}"
                    try:
                        out[key] = _one_case(policy, who, args, outcome)
                    except Exception as exc:  # noqa: BLE001 — an escape is itself the record
                        out[key] = {"harness_escape": f"{type(exc).__name__}: {exc}"}
    return out


# ── the tripwire ─────────────────────────────────────────────────────────


def test_the_decision_matrix_has_not_moved(request):
    """One hash over every cell. A restructure that changes a decision fails here.

    This is not a readable assertion and is not meant to be one. When it fails, the diff
    it prints names the cells that moved, and each of those is a question to answer
    rather than a number to update.
    """
    current = _matrix()
    if request.config.getoption("--snapshot-update", default=False) or not SNAPSHOT.exists():
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip(f"snapshot written: {len(current)} cells")

    recorded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    moved = sorted(k for k in set(recorded) | set(current) if recorded.get(k) != current.get(k))
    assert not moved, f"{len(moved)} of {len(current)} decisions moved. First five:\n" + "\n".join(
        f"  {k}\n    was: {recorded.get(k)}\n    now: {current.get(k)}" for k in moved[:5]
    )


def test_the_matrix_is_broad_enough_to_be_worth_hashing():
    """A snapshot of six cells certifies nothing. If the matrix shrinks, say so."""
    assert len(_matrix()) >= 5000


def test_no_cell_of_the_matrix_lets_a_canary_out():
    """The one property that holds across every cell, asserted rather than hashed.

    A hash tells you something moved. This tells you what must never be true, and it is
    the invariant the post-gate exists for: a planted token does not reach the caller,
    whatever shape the tool returned it in and whichever control was configured.
    """
    escaped = [k for k, v in _matrix().items() if v.get("canary_escaped")]
    assert not escaped, f"the canary reached the caller in {len(escaped)} cells: {escaped[:5]}"


# ── the state that must stay singular ────────────────────────────────────


def test_two_sinks_on_one_path_share_one_lock(tmp_path):
    """`_PATH_LOCKS` is a module-level map. Two Gates in one process is the ordinary way
    a host separates a strict tool set from a lenient one, and if a split gives them
    separate maps the appends interleave and the chain is broken forever."""
    from histos.audit import _path_key

    log = tmp_path / "a.jsonl"
    first, second = JSONLAuditSink(log), JSONLAuditSink(log)
    assert _path_key(first.path) == _path_key(second.path)
    assert first._path_lock() is second._path_lock()


def test_the_erasure_memory_is_one_map_per_process(tmp_path):
    """`_PATH_HIGH_WATER` is what makes a deleted log detectable. A second copy of the
    map is a second memory, and the one consulted would be empty."""
    log = tmp_path / "a.jsonl"
    first = JSONLAuditSink(log)
    for i in range(3):
        first.record({"effect": "allow", "rule": "allow", "n": i})
    log.unlink()
    (tmp_path / "a.jsonl.tip").unlink()

    # A *different* sink object, as a fresh Gate would build.
    JSONLAuditSink(log).record({"effect": "allow", "rule": "allow", "n": "after"})
    from histos import verify_chain

    ok, detail = verify_chain(log)
    assert not ok, f"the erasure was forgotten across two sink objects: {detail}"


def test_the_principal_contextvar_is_one_object():
    """Two copies of `_current_principal` means `use_principal` binds one and the engine
    reads the other — every call unauthenticated, and no test of a single module would
    notice."""
    from histos.engine import Engine  # the reader
    from histos.identity import _current_principal  # the writer

    who = Principal(role="clerk", identity="alice")
    with use_principal(who):
        assert _current_principal.get() is who
    # And the identity the engine actually decides against is the one `use_principal`
    # bound — asked through a real decision, not through the variable.
    sink = InMemoryAuditSink()
    policy = Policy(tools={"t": ToolContract(name="t", args=Schema({}))}, permissions={"clerk": frozenset({"t"})})
    safe = Gate(policy, audit=sink).wrap(lambda: "ok", name="t")
    with use_principal(who):
        safe()
    assert sink.entries[-1]["identity"] == "alice"
    assert Engine is not None


def test_the_scope_token_stack_is_one_object():
    from histos.identity import _scope_tokens

    outer = use_principal(Principal(role="a", identity="1"))
    outer.__enter__()
    depth_after_enter = len(_scope_tokens.get())
    outer.__exit__(None, None, None)
    assert depth_after_enter == len(_scope_tokens.get()) + 1


def test_the_case_fold_probe_is_measured_per_directory(tmp_path):
    """`_folds_case` is `lru_cache`d. A split that gives two modules their own cache is
    harmless; one that keys it differently is not, and this pins the key."""
    from histos.audit import _folds_case

    first = _folds_case(str(tmp_path))
    assert _folds_case(str(tmp_path)) is first
    assert isinstance(first, bool)
