"""Run the language-neutral conformance corpus against the reference engine.

The corpus in `conformance/` defines what "the same policy behaves the same way"
means across implementations. It lives here, in the reference engine's own suite, so
a Python change that breaks the contract fails **this suite, today**, rather than the
TypeScript port eighteen months from now. That is the difference between a corpus
and a description of what an engine used to do. (Automating the suite itself is
known debt D2 — until then "today" means "the next time somebody runs pytest".)

`conformance/manifest.json` is what a second implementation reads: it pins the exact
case list, a hash per fixture, and what "passes" is allowed to mean. It is verified
against the directory here, so it cannot drift into describing a corpus that no
longer exists.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from histos import (
    SUPPORTED_SCHEMA_VERSIONS,
    Effect,
    Gate,
    GateRequest,
    Policy,
    PolicyError,
    Principal,
    contract_hash,
    description_hash,
    load_bundle,
    load_bundle_json,
    load_bundle_yaml,
    schema_hash,
    sources_from_mcp,
    sources_from_openai,
)

CORPUS = Path(__file__).resolve().parent.parent / "conformance"


def _cases(sub: str) -> list[tuple[str, dict]]:
    files = sorted((CORPUS / sub).glob("*.json"))
    assert files, f"conformance/{sub}/ is empty — the corpus must not silently vanish"
    return [(f.stem, json.loads(f.read_text(encoding="utf-8"))) for f in files]


def _ids(cases):
    return [name for name, _ in cases]


# ── decisions ────────────────────────────────────────────────────────────

DECISIONS = _cases("decisions")


@pytest.mark.parametrize("name,case", DECISIONS, ids=_ids(DECISIONS))
def test_decision_corpus(name, case):
    policy = load_bundle(case["policy"])
    resource = case.get("resource")
    resolver = (lambda tool, args: dict(resource)) if resource is not None else None
    gate = Gate(policy, resource_resolver=resolver)

    spec = case.get("principal")
    principal = (
        Principal(
            role=spec["role"],
            identity=spec.get("identity"),
            attributes=spec.get("attributes", {}),
            can_view=frozenset(spec.get("can_view", [])),
        )
        if spec is not None
        else None
    )

    call = case["call"]
    expect = case["expect"]

    if principal is None:
        # "no identity bound" is a wrapper-level decision, so drive it through a tool.
        def tool(**kwargs):  # pragma: no cover - never reached when the gate works
            return None

        wrapped = gate.wrap(tool, name=call["tool"])
        with pytest.raises(Exception) as exc:  # noqa: PT011 - GateDenied, asserted below
            wrapped(**call["args"])
        assert exc.value.decision.rule == expect["rule"]
        return

    args = dict(call["args"])
    denial = gate._apply_bindings(call["tool"], principal, args)  # noqa: SLF001 - the corpus tests the real path
    decision = denial or gate.engine.pre(GateRequest(call["tool"], args, principal))

    assert decision.effect is Effect(expect["effect"]), f"{name}: {decision.explain()}"
    assert decision.rule == expect["rule"], f"{name}: {decision.explain()}"
    if "field" in expect:
        assert decision.field == expect["field"]
    if "bound_args" in expect:
        for key, value in expect["bound_args"].items():
            assert args[key] == value, f"{name}: binding did not override {key!r}"


# ── canonicalization ─────────────────────────────────────────────────────

CANON = _cases("canonicalization")


@pytest.mark.parametrize("name,case", CANON, ids=_ids(CANON))
def test_canonicalization_corpus(name, case):
    """Every spelling of one policy must produce one hash.

    Engines rarely diverge on a verdict; they diverge here, and then approvals bound
    to a policy hash quietly stop matching between services.
    """
    hashes = set()
    for doc in case["documents"]:
        loader = load_bundle_yaml if doc["format"] == "yaml" else load_bundle_json
        hashes.add(loader(doc["text"]).content_hash())
    assert len(hashes) == 1, f"{name}: {len(hashes)} distinct hashes for one logical policy"


# ── invalid policy ───────────────────────────────────────────────────────

INVALID = _cases("invalid-policy")


@pytest.mark.parametrize("name,case", INVALID, ids=_ids(INVALID))
def test_invalid_policy_corpus(name, case):
    with pytest.raises(PolicyError) as exc:
        load_bundle(case["document"])
    assert exc.value.code == case["expect"]["code"], f"{name}: got code {exc.value.code!r} — {exc.value}"


# ── the corpus itself ────────────────────────────────────────────────────


def test_every_expected_code_is_in_the_published_vocabulary():
    """A fixture must not invent a code the spec does not define."""
    vocab = json.loads((CORPUS.parent / "spec" / "decision-codes.json").read_text(encoding="utf-8"))
    runtime = {c["code"] for c in vocab["codes"]}
    policy_codes = set(vocab["policy_codes"])

    for name, case in DECISIONS:
        rule = case["expect"]["rule"]
        assert rule in runtime, f"{name}: {rule!r} is not a published RUNTIME code"
    for name, case in INVALID:
        code = case["expect"]["code"]
        assert code in policy_codes, f"{name}: {code!r} is not a published POLICY code"


# ── projection ───────────────────────────────────────────────────────────

PROJECTION = _cases("projection")
_READERS = {"mcp": sources_from_mcp, "openai": sources_from_openai}


@pytest.mark.parametrize("name,case", PROJECTION, ids=_ids(PROJECTION))
def test_projection_corpus(name, case):
    """One tool definition in, one contract and three hashes out.

    This is what stops a second implementation from importing the same schema
    differently. A bridge that drops `minLength` still reaches the same verdicts —
    it just reports drift the reference engine does not, which turns a security
    signal into noise.
    """
    sources = _READERS[case["kind"]](case["source"])
    assert len(sources) == 1, f"{name}: a projection case describes exactly one tool"
    source = sources[0]
    expect = case["expect"]

    assert source.contract.shape_fingerprint() == expect["contract"], f"{name}: projected contract differs"
    assert schema_hash(source.shape) == expect["schema_sha256"], f"{name}: schema_sha256 differs"
    assert description_hash(source.description) == expect["description_sha256"], f"{name}: description_sha256"
    assert contract_hash(source.contract) == expect["contract_sha256"], f"{name}: contract_sha256 differs"


def test_projection_numeric_spelling_does_not_change_the_contract_hash():
    """`1` and `1.0` must hash alike — `JSON.parse` cannot tell them apart."""
    by_name = dict(PROJECTION)
    written_as_float = by_name["integral-bounds-hash-the-same-whether-written-as-int-or-float"]
    written_as_int = by_name["integral-bounds-written-as-int"]
    assert written_as_float["expect"]["contract_sha256"] == written_as_int["expect"]["contract_sha256"]


def test_absent_description_is_distinguishable_from_an_empty_one():
    """A tool that gains an empty description has changed, and must say so."""
    assert description_hash(None) != description_hash("")


# ── the manifest ─────────────────────────────────────────────────────────

CORPORA = ("decisions", "canonicalization", "invalid-policy", "projection")


def _corpus_index() -> dict:
    """The mechanical half of `manifest.json`, recomputed from what is on disk."""
    index = {}
    for sub in CORPORA:
        cases = []
        for path in sorted((CORPUS / sub).glob("*.json")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            cases.append({"case": path.stem, "file": f"{sub}/{path.name}", "sha256": digest})
        index[sub] = cases
    return index


def test_manifest_lists_exactly_the_corpus_on_disk():
    """A manifest that drifts is worse than none — it certifies a corpus nobody runs.

    Regenerate with:
        python -c "import tests.test_conformance as t; t.print_manifest_index()"
    """
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    expected = _corpus_index()

    for sub in CORPORA:
        listed = manifest["corpora"][sub]["cases"]
        assert listed == expected[sub], (
            f"{sub}: manifest.json does not match the directory — "
            f"{len(listed)} listed vs {len(expected[sub])} on disk, or a fixture changed content"
        )

    assert manifest["totals"] == {sub: len(expected[sub]) for sub in CORPORA} | {
        "all": sum(len(v) for v in expected.values())
    }


def test_manifest_pins_the_version_the_engine_actually_supports():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] in SUPPORTED_SCHEMA_VERSIONS
    for level in manifest["levels"].values():
        for sub in level["corpora"]:
            assert sub in CORPORA, f"level references unknown corpus {sub!r}"


def print_manifest_index() -> None:  # pragma: no cover - a developer convenience
    """Print the regenerated mechanical half, to paste into `manifest.json`."""
    index = _corpus_index()
    print(json.dumps({"corpora": index, "totals": {s: len(c) for s, c in index.items()}}, indent=2))


def test_shipped_example_policy_parses_under_the_corpus_rules():
    """The example in the README must be a valid Draft 0.1 document."""
    policy = Policy()
    assert isinstance(policy, Policy)
    from histos import load_policy

    example = CORPUS.parent / "examples" / "security.policy.yaml"
    loaded = load_policy(example)
    assert loaded.schema_version == "histos.policy/0.1"
    assert loaded.validate() == []
