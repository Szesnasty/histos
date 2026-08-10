"""The `policies/` gallery is documentation that has to keep working.

Every published policy is a claim about the format, so each one is loaded, validated
and — the part worth automating — checked against its JSON twin. "The same policy in
YAML and in JSON hashes to one value" is the property approvals and policy pinning
rest on; a gallery that quietly stopped demonstrating it would be worse than none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from histos import SUPPORTED_SCHEMA_VERSIONS, load_bundle_json, load_policy

GALLERY = Path(__file__).resolve().parent.parent / "policies"
POLICIES = sorted(GALLERY.glob("*.policy.yaml"))


def _stem(path: Path) -> str:
    return path.name.removesuffix(".policy.yaml")


def test_the_gallery_is_not_empty():
    assert POLICIES, "policies/ is empty — the gallery must not silently vanish"


@pytest.mark.parametrize("src", POLICIES, ids=[_stem(p) for p in POLICIES])
def test_every_policy_loads_and_validates(src: Path):
    policy = load_policy(src)
    assert policy.schema_version in SUPPORTED_SCHEMA_VERSIONS
    assert policy.validate() == [], f"{src.name} does not validate"


@pytest.mark.parametrize("src", POLICIES, ids=[_stem(p) for p in POLICIES])
def test_the_json_twin_hashes_identically(src: Path):
    """Two spellings, one hash — including key order and explicitly stated defaults.

    The twins are emitted with their keys in reversed order precisely so this is a
    demonstration rather than a tautology, and `01-minimal` additionally spells out
    several defaults the YAML omits.
    """
    twin = src.with_name(f"{_stem(src)}.policy.json")
    assert twin.exists(), f"{src.name} has no JSON twin"

    assert load_bundle_json(twin.read_text(encoding="utf-8")).content_hash() == load_policy(src).content_hash(), (
        f"{_stem(src)}: the YAML and JSON spellings disagree on content_hash"
    )


@pytest.mark.parametrize("src", POLICIES, ids=[_stem(p) for p in POLICIES])
def test_every_declared_feature_is_one_the_engine_implements(src: Path):
    """`requires.features` is a load-time assertion, so a typo must not pass silently."""
    import yaml  # the gallery is YAML by definition; the dev extra provides this

    from histos import ENGINE_FEATURES

    raw = yaml.safe_load(src.read_text(encoding="utf-8"))
    for feature in raw.get("requires", {}).get("features", []):
        assert feature in ENGINE_FEATURES, f"{src.name}: {feature!r} is not an engine feature"


def test_each_policy_is_a_distinct_document():
    """A copy-paste that left two files identical would make the gallery a lie."""
    hashes = {_stem(p): load_policy(p).content_hash() for p in POLICIES}
    assert len(set(hashes.values())) == len(hashes), f"duplicate policies: {hashes}"
