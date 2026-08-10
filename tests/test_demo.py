"""The README killer demo must actually bound a hijacked agent (Phase 0.1)."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_demo():
    path = Path(__file__).resolve().parent.parent / "examples" / "makeRefund_demo.py"
    spec = importlib.util.spec_from_file_location("makeRefund_demo", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_composite_demo_bounds_a_hijacked_agent():
    results = dict(_load_demo().run())
    # RBAC passed each time; the composite still bounded the agent:
    assert "arg_schema" in results["huge refund"]  # value bound stops the drain
    assert results["await confirm"] == "CONFIRMATION_REQUIRED"  # high-risk write needs a human
    assert "'status': 'refunded'" in results["approved+run"]  # runs after approval
    assert "card" not in results["approved+run"]  # leaked PAN stripped before the model
    assert "internal_token" not in results["approved+run"]  # leaked token stripped too
    assert "resource_constraint" in results["cross-tenant"]  # can't touch another tenant's order
