"""Shared fixtures and helpers for the histos test suite."""

from __future__ import annotations

import pytest

from histos import Constraint, Field, Policy, Schema, Sensitivity, ToolContract

# A fixed HMAC key so audit digests are deterministic across a test run.
STABLE_KEY = b"histos-test-key-0123456789abcd"


class FakeClock:
    """A hand-cranked monotonic clock for deterministic limit tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def sample_resolver():
    """The trusted resource store behind `sample_policy`'s ownership constraint."""
    invoices = {1: {"tenant_id": "acme"}, 2: {"tenant_id": "acme"}, 99: {"tenant_id": "rival"}}

    def resolve(tool: str, args: dict) -> dict:
        return invoices.get(args.get("invoice_id"), {})

    return resolve


@pytest.fixture
def sample_policy() -> Policy:
    """A small, realistic policy: a read tool, a destructive write, tenant scoping."""
    return Policy(
        tools={
            "get_order": ToolContract(
                name="get_order",
                args=Schema({"order_id": Field(type="integer")}),
                returns=Schema({"total": Field(type="number"), "email": Field(type="string", sensitive="pii")}),
                access="read",
            ),
            "delete_invoice": ToolContract(
                name="delete_invoice",
                args=Schema({"invoice_id": Field(type="integer")}),
                access="write",
                sensitivity=Sensitivity.CRITICAL,
                # Resource-bound: ownership comes from the resolver, not the argument.
                constraints=(Constraint.owns("tenant_id"),),
            ),
        },
        permissions={
            "viewer": frozenset({"get_order"}),
            "billing": frozenset({"delete_invoice"}),
            "admin": frozenset({"get_order"}),
        },
        role_inherits={"admin": "billing"},  # admin inherits delete_invoice
        canaries=frozenset({"CANARY-7f3a-SECRET"}),
        policy_version="1",
    )
