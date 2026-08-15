"""Refusing a pattern that can be made to run for hours, at policy-load time.

An argument `pattern` is attacker-influenced input: it arrives from an imported MCP or
OpenAPI schema, written by whatever server the host pointed at. `re` has no step budget
and does not release the GIL, so one crafted argument against a pathological pattern
stalls the whole process — which is why this is a load-time refusal with a named rewrite
rather than a runtime timeout there is no way to implement.

Three parts, in the order they run:

* :mod:`histos.redos.alphabet` — what characters each piece of a parsed pattern can
  match, and where two pieces can touch. Everything else is expressed in those terms.
* :mod:`histos.redos.shapes` — the structural screen: nesting, adjacent repeats over
  overlapping alphabets, and the separators that make an apparently ambiguous boundary
  determined after all.
* :mod:`histos.redos.probe` — a load-time timing ladder, because a structural screen
  predicts and a measurement does not have to.

The screen is conservative in one direction by design: it can refuse a pattern that
would have been fine. SECURITY.md names the false positives it is known to have.
"""

from __future__ import annotations

from histos.redos.probe import reject_catastrophic_backtracking

__all__ = ["reject_catastrophic_backtracking"]
