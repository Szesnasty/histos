"""The README killer demo must actually bound a hijacked agent (Phase 0.1)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


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


@pytest.mark.parametrize("script", ["sweep.py", "tally.py", "validate.py"])
def test_sweep_tools_have_a_non_executing_help_path(script):
    """`--help` must not start models, treat the flag as a filename, or run validation.

    These are operator-facing commands. A typo should be rejected by argparse and a
    help request must be free; previously one crashed, one tried to open `--help`, and
    one silently launched six model scenarios.
    """
    path = Path(__file__).resolve().parent.parent / "demo" / "sweep" / script
    proc = subprocess.run([sys.executable, str(path), "--help"], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in proc.stdout
    assert "Traceback" not in proc.stderr


def test_sweep_cannot_report_success_when_the_budget_stops_an_incomplete_grid(tmp_path, monkeypatch, capsys):
    path = Path(__file__).resolve().parent.parent / "demo" / "sweep" / "sweep.py"
    spec = importlib.util.spec_from_file_location("demo_sweep_budget_test", path)
    assert spec and spec.loader
    sweep = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sweep)

    monkeypatch.setattr(sweep, "cells", lambda: [("clinic", "paid-model", 0.0, True, 0)])
    monkeypatch.setattr(sweep, "revision", lambda: {"commit": "abc", "dirty": False})
    monkeypatch.setattr(sweep, "BUDGET_USD", 0.0)

    assert sweep.main([str(tmp_path / "results.jsonl")]) == 1
    out = capsys.readouterr().out
    assert "STOPPED" in out
    assert "SWEEP INCOMPLETE" in out
    assert "SWEEP COMPLETE" not in out


def test_control_tally_separates_feature_cost_from_safe_utility():
    path = Path(__file__).resolve().parent.parent / "demo" / "sweep" / "tally.py"
    spec = importlib.util.spec_from_file_location("demo_tally_control_test", path)
    assert spec and spec.loader
    tally = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tally)

    requested_carer = {
        "damage": False,
        "utility": {"to_requested": True, "to_authorised": True},
    }
    rebound_to_caller = {
        "damage": False,
        "utility": {"to_requested": False, "to_authorised": True},
    }
    assert tally._cell("clinic-cost", "control", [{"wirings": [requested_carer]}], 0) == "1/1 1/1"
    assert tally._cell("clinic-cost", "control", [{"wirings": [rebound_to_caller]}], 0) == "0/1 1/1"
