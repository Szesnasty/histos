"""The policy document: what it may say, how it is parsed, and how it is written back.

A bundle is the artifact a human reviews and signs off, which sets every rule in here.
An unrecognised key is a refusal, because the alternative is a document whose author
believes it constrains something it does not. Both parsers are less permissive than
their libraries, because JSON keeps the last of a repeated key while a human greps the
first, and YAML 1.1 reads `no` as False. And the dump has to round-trip exactly, because
`histos import --update` re-runs it every time — so a field it loses converges on a
policy weaker than the one that was reviewed.
"""

from histos.format.bundle import (
    load_bundle,
    load_bundle_json,
    load_bundle_yaml,
    load_policy,
    merge_contracts,
)
from histos.format.bundledump import dump_bundle
from histos.format.bundlekeys import ENGINE_FEATURES, SUPPORTED_SCHEMA_VERSIONS
from histos.format.bundleparse import parse_json_bundle, parse_yaml_bundle

__all__ = [
    "ENGINE_FEATURES",
    "SUPPORTED_SCHEMA_VERSIONS",
    "dump_bundle",
    "load_bundle",
    "load_bundle_json",
    "load_bundle_yaml",
    "load_policy",
    "merge_contracts",
    "parse_json_bundle",
    "parse_yaml_bundle",
]
