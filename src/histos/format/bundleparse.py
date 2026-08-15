"""Turning bytes into a mapping, strictly, before anything reads it.

Split out of `bundle.py`. Both parsers are deliberately less permissive than their
libraries. JSON silently keeps the *last* of a repeated key while a human greps the
first, so a repeat is refused; `NaN` and `Infinity` are not JSON and are refused too.
YAML is worse: its 1.1 bool resolver reads `no` and `off` as `False`, so a tool named
`no` becomes a boolean key, and its tag machinery constructs arbitrary Python objects.
Only the plain scalar types survive here.
"""

from __future__ import annotations

import json
import re
from typing import Any

from histos.errors import PolicyError
from histos.format.bundlekeys import _reject_expansion_bomb

# ── canonical parsing ──────────────────────────────────────────
#
# "The same security.policy.yaml behaves identically in Python and TypeScript" is
# only true if *loading* is specified rather than left to whatever a given parser
# happens to do. So parsing is strict and the canonical model — not the parser —
# is normative:
#
#   * duplicate keys are a PolicyError, never "last one wins";
#   * YAML 1.1's `yes`/`no`/`on`/`off` do NOT silently become booleans, so a YAML
#     bundle and the equivalent JSON produce the identical `content_hash`;
#   * YAML is loaded through a vetted parser behind the optional [yaml] extra —
#     we never hand-roll a parser for a security artifact.
#
# Honest scope: this normalizes the divergences that actually bite a policy file
# (duplicate keys, the YAML bool set). It is not a full YAML-1.1-vs-1.2
# reconciliation — exotic scalars (sexagesimals, underscore-separated ints) are
# not remapped. Quote anything you mean as a string.


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise PolicyError(
                f"duplicate key {key!r} in policy — refusing to guess which one wins", code="duplicate_key"
            )
        seen.add(key)
    return dict(pairs)


def _reject_json_constant(token: str) -> Any:
    """`NaN` / `Infinity` / `-Infinity` are Python's extension, not JSON.

    They are also the one literal that can express a bound which parses, hashes and
    validates cleanly and then never fires — every comparison against NaN is False.
    Refusing them at parse time keeps the failure at the line that wrote it.
    """
    raise PolicyError(
        f"policy contains the non-standard JSON literal {token} — a bound written this way "
        "would load and then never reject anything. Write a real number, or omit the bound.",
        code="unparseable",
    )


_TOO_DEEP = (
    "policy is nested too deeply to parse — refusing to load. A document that exhausts the parser is "
    "not one this engine can enforce only part of."
)


def parse_json_bundle(text: str) -> dict[str, Any]:
    """Strictly parse a JSON bundle into a dict (duplicate keys are refused)."""
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}", code="unparseable") from exc
    except RecursionError as exc:
        # A deeply nested document exhausts the interpreter stack inside the parser, and
        # a raw RecursionError walks straight past every `except PolicyError` a host
        # wrote around loading — including the CLI's, which then prints a traceback for
        # what is an ordinary malformed input. Same code as the expansion bomb: one
        # family, one thing for a host to catch.
        raise PolicyError(_TOO_DEEP, code="policy_too_large") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy must be an object at the top level, got {type(data).__name__}", code="not_an_object")
    return data


# Only the JSON-compatible spellings are booleans. Everything else YAML 1.1 would
# have resolved (`yes`, `no`, `on`, `off`, `y`, `n`) stays the string it looks like.
_JSON_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")

_yaml_loader_cache: tuple[Any, Any] | None = None


def _strict_yaml_loader() -> tuple[Any, Any]:
    """Build (once) a SafeLoader that rejects duplicate keys and JSON-aligns bools.

    Returns ``(yaml_module, loader_class)``. The module comes back from here rather
    than being imported again by the caller, so the curated "pip install histos[yaml]"
    message is the only thing a user without PyYAML can hit — a second bare
    ``import yaml`` anywhere else would raise ModuleNotFoundError first and make this
    branch dead code.
    """
    global _yaml_loader_cache
    if _yaml_loader_cache is not None:
        return _yaml_loader_cache

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised only without pyyaml
        raise ImportError(
            "YAML bundles need PyYAML: pip install histos[yaml] "
            "(or parse the YAML yourself and call load_bundle(dict))."
        ) from exc

    class StrictLoader(yaml.SafeLoader):
        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
            self.flatten_mapping(node)
            mapping: dict[Any, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in mapping:
                    line = key_node.start_mark.line + 1
                    raise PolicyError(
                        f"duplicate key {key!r} in policy at line {line} — refusing to guess which one wins",
                        code="duplicate_key",
                    )
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    # Replace YAML 1.1's bool resolver with the JSON-compatible one. Copy the
    # table first so SafeLoader itself (and anyone else's YAML) is untouched.
    bool_tag = "tag:yaml.org,2002:bool"
    StrictLoader.yaml_implicit_resolvers = {
        ch: [(tag, regexp) for tag, regexp in resolvers if tag != bool_tag]
        for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    StrictLoader.add_implicit_resolver(bool_tag, _JSON_BOOL, list("tTfF"))

    _yaml_loader_cache = (yaml, StrictLoader)
    return _yaml_loader_cache


def parse_yaml_bundle(text: str) -> dict[str, Any]:
    """Strictly parse a YAML bundle into a dict. Requires the optional ``[yaml]`` extra."""
    yaml, loader = _strict_yaml_loader()
    try:
        # Suppressed for both tools, because S506 and B506 are the same rule in ruff and
        # in bandit and both read `yaml.load(..., Loader=)` as unsafe on sight. `loader`
        # is `StrictLoader`, built above as a `yaml.SafeLoader` subclass that overrides
        # `construct_mapping` to reject duplicate keys and swaps YAML 1.1's bool resolver
        # for the JSON one. It registers no constructor, so no tag can instantiate an
        # object. `yaml.safe_load` takes no loader, which is why this is not that call.
        data = yaml.load(text, Loader=loader)  # noqa: S506  # nosec B506
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}", code="unparseable") from exc
    except RecursionError as exc:  # see parse_json_bundle
        raise PolicyError(_TOO_DEEP, code="policy_too_large") from exc
    if data is None:
        raise PolicyError("policy file is empty", code="unparseable")
    if not isinstance(data, dict):
        raise PolicyError(f"policy must be a mapping at the top level, got {type(data).__name__}", code="not_an_object")
    # Checked here as well as in `load_bundle`, because aliases are a YAML feature and
    # this function is public: whoever parses is holding the bomb.
    _reject_expansion_bomb(data)
    return data
