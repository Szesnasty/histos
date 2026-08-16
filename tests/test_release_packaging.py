"""What ships is what nobody can take back.

A PyPI upload is immutable: the 0.1.0 project page renders whatever long description
0.1.0 was built with, forever, and the sdist is what a distribution packager and an
offline reader unpack. The near miss these tests pin is that 0.1.0 was one upload away
from a page that said "Not on PyPI yet", offered an unpinned `git+https` install, and
linked 25 times into a repository layout PyPI resolves against pypi.org. So the
assertions are made against the *built* distribution wherever they can be, not against
the tree the build happens to start from.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from histos import Principal, load_bundle_yaml, protect, use_principal
from histos._version import __version__

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
README = REPOSITORY_ROOT / "README.md"
MANIFEST = REPOSITORY_ROOT / "MANIFEST.in"
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"

MARKDOWN_LINK = re.compile(r"\]\(([^)]+)\)")
ALREADY_ABSOLUTE = re.compile(r"^(https?:|mailto:|#)")

# Phrases that were true while the package was unpublished and become a lie the moment
# it is. They are checked as text rather than as a review item because a reviewer reads
# the README on GitHub, where relative links work and the install block looks fine.
DENIES_ITS_OWN_RELEASE = (
    "Not on PyPI",
    "not yet on PyPI",
    "git+https://github.com/Szesnasty/histos",
    "Until that tag is published",
    "trusted-publisher workflow completes",
)

# A build writes `src/histos.egg-info`, `build/` and `dist/` beside the sources, and a
# test suite has no business doing that to the tree it is running in — hence the copy,
# and hence the things not worth copying.
NOT_WORTH_COPYING = shutil.ignore_patterns(
    ".git", ".venv", "build", "dist", "*.egg-info", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"
)


def _relative_link_targets(text: str) -> list[str]:
    """Markdown link targets that only resolve inside a repository checkout.

    PyPI renders the long description at `https://pypi.org/project/histos/` and does
    not rewrite relative targets against the source repository the way GitHub does, so
    every one of these is a 404 on the project page.
    """
    # A Python expression such as ``tools["name"](argument)`` contains the same
    # ``](`` delimiter as a Markdown link. It is code, not a target PyPI will resolve.
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    prose = re.sub(r"`[^`\n]*`", "", prose)
    return [t for t in MARKDOWN_LINK.findall(prose) if not ALREADY_ABSOLUTE.match(t)]


def _manifest_promises() -> tuple[list[str], list[str]]:
    """The `include`d files and `graft`ed directories, as MANIFEST.in states them."""
    includes: list[str] = []
    grafts: list[str] = []
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        command, *arguments = line.split()
        if command == "include":
            includes.extend(arguments)
        elif command == "graft":
            grafts.extend(arguments)
    return includes, grafts


class BuiltSdist:
    """A source distribution as `python -m build` produced it: its file list and its PKG-INFO."""

    def __init__(self, names: list[str], pkg_info: str) -> None:
        self.names = names
        self.pkg_info = pkg_info


@pytest.fixture(scope="session")
def sdist(tmp_path_factory: pytest.TempPathFactory) -> BuiltSdist:
    work = tmp_path_factory.mktemp("release")
    source = work / "source"
    shutil.copytree(REPOSITORY_ROOT, source, ignore=NOT_WORTH_COPYING)
    outdir = work / "dist"

    built = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(outdir), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        # Only a missing `build` is a reason to skip. Anything else is the packaging
        # breaking, which is exactly what this file exists to catch.
        if "No module named build" in built.stderr:
            pytest.skip("`python -m build` is not installed in this environment")
        pytest.fail(f"building the sdist failed:\n{built.stdout[-2000:]}\n{built.stderr[-2000:]}")

    (tarball,) = outdir.glob("*.tar.gz")
    with tarfile.open(tarball) as archive:
        # Paths are relative to the `histos-<version>/` root the tarball carries.
        names = sorted(name.split("/", 1)[1] for name in archive.getnames() if "/" in name)
        member = archive.extractfile(f"histos-{__version__}/PKG-INFO")
        assert member is not None, "the sdist has no PKG-INFO"
        pkg_info = member.read().decode("utf-8")
    return BuiltSdist(names, pkg_info)


def test_pkg_info_does_not_deny_its_own_release(sdist: BuiltSdist):
    for phrase in DENIES_ITS_OWN_RELEASE:
        assert phrase not in sdist.pkg_info, f"the long description PyPI will render still says {phrase!r}"


def test_pkg_info_has_no_relative_links(sdist: BuiltSdist):
    dead = sorted(set(_relative_link_targets(sdist.pkg_info)))
    assert not dead, f"these link targets 404 on pypi.org: {dead}"


def test_readme_has_no_relative_links():
    # The same assertion as above against the source file, so the failure names the
    # file to edit even in an environment that cannot build.
    dead = sorted(set(_relative_link_targets(README.read_text(encoding="utf-8"))))
    assert not dead, f"README links must be absolute to survive PyPI rendering: {dead}"


def test_release_workflow_ignores_link_shaped_code():
    """The final inline gate must make the same code/prose distinction as this suite.

    The v0.1.1 release initially stopped after treating
    ``tools["search_docs"](query=...)`` as a relative Markdown link. Keep the
    independently running workflow check aligned with ``_relative_link_targets``.
    """
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'prose = re.sub(r"```.*?```", "", metadata, flags=re.S)' in workflow
    assert 'prose = re.sub(r"`[^`\\n]*`", "", prose)' in workflow
    assert 're.findall(r"\\]\\(([^)]+)\\)", prose)' in workflow


def test_readme_install_section_installs_the_released_package():
    readme = README.read_text(encoding="utf-8")
    for phrase in DENIES_ITS_OWN_RELEASE:
        assert phrase not in readme, f"README still says {phrase!r}"
    install = readme.split("## Install", 1)[1].split("\n## ", 1)[0]
    assert 'pip install "histos[yaml]"' in install
    assert "until" not in install.lower()
    assert "after" not in install.lower()
    assert "git clone" not in install.lower()


def test_the_pypi_readme_contains_a_real_policy_authoring_path(tmp_path: Path):
    """The project page must get a reader from install to an enforceable file.

    The first release showed only a policy assembled with Python constructors. That
    proved the engine but hid the portable artifact the product is built around. Keep
    the YAML on PyPI executable rather than letting it decay into pseudocode.
    """
    readme = README.read_text(encoding="utf-8")
    section = readme.split("## Write a policy", 1)[1].split("\n## ", 1)[0]
    match = re.search(r"```yaml\n(.*?)```", section, flags=re.S)
    assert match is not None, "the PyPI README has no YAML policy example"

    policy = load_bundle_yaml(match.group(1))
    assert policy.validate() == []
    assert set(policy.tools) == {"search_docs"}
    assert policy.permissions == {"support": frozenset({"search_docs"})}
    assert "histos validate security.policy.yaml" in section
    assert "histos review security.policy.yaml" in section
    assert "histos explain security.policy.yaml" in section
    assert "docs/writing-policies.md" in section

    from histos.cli import main

    policy_path = tmp_path / "security.policy.yaml"
    policy_path.write_text(match.group(1), encoding="utf-8")
    assert main(["validate", str(policy_path)]) == 0
    assert main(["review", str(policy_path)]) == 0
    assert (
        main(
            [
                "explain",
                str(policy_path),
                "search_docs",
                "--role",
                "support",
                "--args",
                '{"query":"refund policy"}',
            ]
        )
        == 0
    )

    def search_docs(query: str):
        return {"title": "Refunds", "snippet": "Refunds require a receipt."}

    guarded = protect([search_docs], policy=policy)
    with use_principal(Principal(role="support", identity="reader")):
        assert guarded.tools["search_docs"](query="refund policy") == {
            "title": "Refunds",
            "snippet": "Refunds require a receipt.",
        }


def test_local_markdown_links_resolve_inside_the_repository():
    """A documentation map is useful only while every local target exists."""
    root = README.parent.resolve()
    broken: list[str] = []
    for document in sorted(root.rglob("*.md")):
        if any(part in {".venv", "node_modules", ".git"} for part in document.parts):
            continue
        text = document.read_text(encoding="utf-8")
        # Code examples contain real expressions such as ``tools[…](**args)`` that
        # are valid Markdown-link-shaped text but are not links.
        prose = re.sub(r"```.*?```", "", text, flags=re.S)
        prose = re.sub(r"`[^`\n]*`", "", prose)
        for raw in re.findall(r"\[[^\]\n]+\]\(([^)\n]+)\)", prose):
            target = raw.strip().split(maxsplit=1)[0].strip("<>")
            if re.match(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|#)", target):
                continue
            relative = target.split("#", 1)[0].split("?", 1)[0]
            if not relative:
                continue
            resolved = (document.parent / relative).resolve()
            if root not in (resolved, *resolved.parents) or not resolved.exists():
                broken.append(f"{document.relative_to(root)} -> {target}")

    assert not broken, f"local documentation links do not resolve: {broken}"


def test_manifest_promises_only_paths_that_exist():
    includes, grafts = _manifest_promises()
    assert includes and grafts, "MANIFEST.in ships nothing"
    for promised in [*includes, *grafts]:
        assert (REPOSITORY_ROOT / promised).exists(), f"MANIFEST.in ships {promised}, which is not in the tree"


def test_sdist_ships_what_manifest_promises(sdist: BuiltSdist):
    includes, grafts = _manifest_promises()
    for promised in includes:
        assert promised in sdist.names, f"MANIFEST.in includes {promised}; the sdist does not have it"
    for directory in grafts:
        assert any(name.startswith(f"{directory}/") for name in sdist.names), f"the sdist has no {directory}/"


def test_sdist_ships_the_reading_the_long_description_sends_people_to(sdist: BuiltSdist):
    # Named individually rather than derived from MANIFEST.in: these are the files the
    # README calls the most useful in the repository, and dropping one from the graft
    # list would otherwise make this test agree with the mistake.
    for promised in (
        "SECURITY.md",
        "CHANGELOG.md",
        "docs/writing-policies.md",
        "examples/quickstart.py",
        "conformance/manifest.json",
    ):
        assert promised in sdist.names, f"a `pip download` consumer cannot read {promised}"


def test_sdist_does_not_half_ship_the_test_suite(sdist: BuiltSdist):
    # setuptools' default discovery grabs `tests/test*.py` and nothing else — no
    # conftest.py, no conformance corpus, no policy gallery — which shipped a suite
    # that died at collection. MANIFEST.in prunes tests deliberately; if that decision
    # is ever reversed, it has to be reversed completely, and this is the reminder.
    shipped_tests = [name for name in sdist.names if name.startswith("tests/")]
    assert not shipped_tests, f"the sdist ships {len(shipped_tests)} test files it cannot run"


def test_sdist_carries_no_earlier_builds_egg_info(sdist: BuiltSdist):
    # SOURCES.txt is written by setuptools after MANIFEST.in is processed and describes
    # this build; PKG-INFO and requires.txt would be leftovers from an older one.
    stale = [name for name in sdist.names if name.startswith("src/histos.egg-info/") and "SOURCES.txt" not in name]
    assert not stale, f"the sdist carries a previous build's metadata: {stale}"


def test_the_changelog_never_claims_a_release_that_did_not_happen():
    """A dated heading is released, or the one Release Please candidate.

    This test used to require a dated heading matching `__version__`, and that is how
    `## [0.1.0] - 2026-08-12` came to describe a release that never happened: the gate
    demanded evidence of a release as the precondition for making one, so the only way
    to satisfy it was to write the evidence first. Three days later the changelog
    described a published artifact, twenty-one README links pointed at a tag that did
    not exist, and two adversarial passes were missing from the file whose whole job is
    saying what changed.

    Release Please necessarily writes the candidate heading in its PR before creating
    the tag. That one intermediate state is identified by the manifest already tracking
    the same source version. Every older dated heading still needs a tag. Before the
    first release, the detailed record lives under `Pre-release history` and makes no
    shipped claim.
    """
    changelog = CHANGELOG.read_text(encoding="utf-8")
    dated = re.findall(r"^## \[?(\d+\.\d+\.\d+)\]?(.*)$", changelog, flags=re.M)
    for name, rest in dated:
        assert re.search(r"\d{4}-\d{2}-\d{2}", rest), f"the {name} heading carries no release date: {rest!r}"
        assert "unreleased" not in rest.lower(), f"{name} is both dated and unreleased"

    tagged = _git_tags()
    manifest = json.loads((CHANGELOG.parent / ".release-please-manifest.json").read_text(encoding="utf-8"))["."]
    if tagged is not None:
        unbacked = [name for name, _ in dated if f"v{name}" not in tagged and name != manifest]
        assert not unbacked, (
            f"the changelog says {unbacked} shipped and there is no tag for it. "
            "Only the version currently tracked by Release Please may be a pre-tag candidate."
        )

    if manifest == "0.0.0":
        assert _section_body(changelog, "## [Pre-release history]").strip()
    else:
        assert any(name == __version__ for name, _ in dated), (
            f"Release Please tracks {manifest}, but the changelog has no {__version__} candidate"
        )


def _git_tags() -> set[str] | None:
    """The repository's tags, or None when there is no repository to ask (an sdist)."""
    import subprocess

    try:
        done = subprocess.run(  # noqa: S603 — a fixed argv, no shell
            ["git", "tag", "--list"],  # noqa: S607 — git is on PATH wherever this runs
            capture_output=True,
            text=True,
            cwd=CHANGELOG.parent,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return set(done.stdout.split()) if done.returncode == 0 else None


def _section_body(changelog: str, heading: str) -> str:
    start = changelog.find(heading)
    if start == -1:
        return ""
    end = changelog.find("\n## ", start + len(heading))
    return changelog[start + len(heading) : end if end != -1 else len(changelog)]


def test_release_workflow_publishes_without_a_long_lived_token():
    assert RELEASE_WORKFLOW.exists(), "there is no release workflow; the published artifact is ungated"
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "branches: [main]" in workflow
    assert 'tags: ["v*"]' not in workflow, "pushing an arbitrary tag must not start an upload"
    assert "release_tag:" in workflow, "a failed post-tag release needs an explicit recovery path"
    assert "git describe --tags --exact-match HEAD" in workflow
    assert re.search(r"googleapis/release-please-action@[0-9a-f]{40}\b", workflow)
    assert "needs.release-please.outputs.release_created == 'true'" in workflow
    assert "issues: write" in workflow
    assert "pull-requests: write" in workflow
    assert "id-token: write" in workflow, "Trusted Publishing needs an OIDC token"
    assert "pypa/gh-action-pypi-publish" in workflow
    assert "twine check" in workflow
    # An API token in the workflow would be a credential that outlives the run and can
    # push a release nothing links back to a commit.
    assert "PYPI_API_TOKEN" not in workflow
    assert "password:" not in workflow


def test_every_github_action_is_pinned_to_an_immutable_commit():
    root = RELEASE_WORKFLOW.parent.parent.parent
    uses: list[tuple[Path, str]] = []
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        for action in re.findall(r"^\s*uses:\s*([^\s#]+)", path.read_text(encoding="utf-8"), flags=re.M):
            uses.append((path, action))

    assert uses, "the repository has no GitHub Actions to audit"
    mutable = [f"{path.name}: {action}" for path, action in uses if not re.search(r"@[0-9a-f]{40}$", action)]
    assert not mutable, f"actions execute mutable upstream refs: {mutable}"

    dependabot = (root / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: github-actions" in dependabot


def test_release_please_tracks_the_real_version_file_and_plain_v_tags():
    root = RELEASE_WORKFLOW.parent.parent.parent
    config = json.loads((root / "release-please-config.json").read_text(encoding="utf-8"))
    manifest = json.loads((root / ".release-please-manifest.json").read_text(encoding="utf-8"))
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    package = config["packages"]["."]

    # Before the first public release the manifest records that no release exists.
    # The bootstrap commit carries `Release-As: 0.1.0`; Release Please changes this to
    # the source version in the release PR. Keep the assertion valid on both sides of
    # that one-time transition, while refusing an arbitrary stale version.
    assert manifest in ({".": "0.0.0"}, {".": __version__})
    if manifest["."] == "0.0.0":
        assert re.fullmatch(r"[0-9a-f]{40}", config["bootstrap-sha"])
    assert package["release-type"] == "python"
    assert package["package-name"] == "histos"
    assert package["include-component-in-tag"] is False
    assert package["include-v-in-tag"] is True
    assert {"type": "generic", "path": "src/histos/_version.py"} in package["extra-files"]
    assert "x-release-please-version" in (root / "src/histos/_version.py").read_text(encoding="utf-8")
    if manifest["."] == "0.0.0":
        # Release Please's changelog updater recognises a bracketed H2 as an
        # insertion point. Without one on the first release it creates another
        # `# Changelog` and demotes the entire existing document by one level.
        assert "## [Pre-release history]" in changelog
    else:
        assert re.search(rf"^## \[?{re.escape(__version__)}\]?\b", changelog, flags=re.M)


def test_no_document_links_at_a_ref_that_does_not_exist():
    """Every GitHub link must resolve, and the README is rendered once on PyPI.

    Twenty-six of them pointed at `v0.1.0`, a tag nobody had cut — twenty-one under
    `blob/` and five under `tree/`. Fixing the first spelling and missing the second is
    the shape this project keeps finding in its own code, so it is asked here as a rule:
    any ref that is not `main` must be a tag that exists, and every path behind such a
    link must be a real file in the tree.
    """
    import re

    root = CHANGELOG.parent
    tags = _git_tags()
    bad_refs: list[str] = []
    missing_paths: list[str] = []
    for document in sorted(root.rglob("*.md")):
        if any(part in {".venv", "node_modules", ".git"} for part in document.parts):
            continue
        for ref, path in re.findall(
            r"github\.com/Szesnasty/histos/(?:blob|tree|raw)/([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]*)",
            document.read_text(encoding="utf-8"),
        ):
            where = f"{document.relative_to(root)} -> {ref}/{path}"
            if ref != "main" and tags is not None and ref not in tags:
                bad_refs.append(where)
            if path and not (root / path).exists():
                missing_paths.append(where)

    assert not bad_refs, f"links point at a ref that does not exist: {bad_refs}"
    assert not missing_paths, f"links point at paths that are not in the tree: {missing_paths}"


def test_the_readme_does_not_announce_a_release_that_has_not_happened():
    """The third document that claimed 0.1.0 shipped, and the last one found by hand.

    The changelog gate above says a dated entry needs a tag behind it. The README says
    the same thing in prose — a status table cell — and prose was not covered, so while
    the changelog was corrected the table went on reading "released, 0.1.0" for another
    commit. A reviewer found it. Same rule, applied to the same claim wherever it is
    written: nothing may announce a version that has no tag.
    """
    import re

    readme = (CHANGELOG.parent / "README.md").read_text(encoding="utf-8")
    tags = _git_tags()
    if tags is None:  # no repository to ask — an sdist
        return
    # `(?<!un)` because the honest spelling is *unreleased*, and a pattern that
    # matched it too failed on the corrected file — the first version of this
    # check called the fix a violation.
    announced = re.findall(r"(?<!un)released,?\s+v?(\d+\.\d+\.\d+)", readme, flags=re.I)
    unbacked = [v for v in announced if f"v{v}" not in tags]
    assert not unbacked, (
        f"README announces {unbacked} as released and there is no tag for it. "
        "Say 'unreleased' until the release workflow cuts one."
    )
