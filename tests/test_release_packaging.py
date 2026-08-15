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

import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

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
DENIES_ITS_OWN_RELEASE = ("Not on PyPI", "not yet on PyPI", "git+https://github.com/Szesnasty/histos")

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
    return [t for t in MARKDOWN_LINK.findall(text) if not ALREADY_ABSOLUTE.match(t)]


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


def test_readme_install_section_installs_the_released_package():
    readme = README.read_text(encoding="utf-8")
    for phrase in DENIES_ITS_OWN_RELEASE:
        assert phrase not in readme, f"README still says {phrase!r}"
    assert 'pip install "histos[yaml]"' in readme


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
    for promised in ("SECURITY.md", "CHANGELOG.md", "examples/quickstart.py", "conformance/manifest.json"):
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
    """A dated heading says "this version shipped". Nothing may say that before it did.

    This test used to require a dated heading matching `__version__`, and that is how
    `## [0.1.0] - 2026-08-12` came to describe a release that never happened: the gate
    demanded evidence of a release as the precondition for making one, so the only way
    to satisfy it was to write the evidence first. Three days later the changelog
    described a published artifact, twenty-one README links pointed at a tag that did
    not exist, and two adversarial passes were missing from the file whose whole job is
    saying what changed.

    So it asks the other way round now. A dated entry must have a tag behind it, and the
    version being built must be described *somewhere* — under its own heading once it
    ships, under `[Unreleased]` until then. Both states are honest; the one in between
    is not.
    """
    changelog = CHANGELOG.read_text(encoding="utf-8")
    headings = re.findall(r"^## \[([^\]]+)\](.*)$", changelog, flags=re.M)
    assert headings, "the changelog has no version headings at all"

    dated = [(name, rest) for name, rest in headings if name != "Unreleased"]
    for name, rest in dated:
        assert re.search(r"\d{4}-\d{2}-\d{2}", rest), f"the {name} heading carries no release date: {rest!r}"
        assert "unreleased" not in rest.lower(), f"{name} is both dated and unreleased"

    tagged = _git_tags()
    if tagged is not None:
        unbacked = [name for name, _ in dated if f"v{name}" not in tagged]
        assert not unbacked, (
            f"the changelog says {unbacked} shipped and there is no tag for it. "
            "Either cut the tag or move the entry back under [Unreleased]."
        )

    described = any(name == __version__ for name, _ in dated) or _unreleased_body(changelog).strip()
    assert described, f"the build is {__version__} and the changelog says nothing about it"


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


def _unreleased_body(changelog: str) -> str:
    start = changelog.find("## [Unreleased]")
    if start == -1:
        return ""
    end = changelog.find("\n## [", start + 1)
    return changelog[start + len("## [Unreleased]") : end if end != -1 else len(changelog)]


def test_release_workflow_publishes_without_a_long_lived_token():
    assert RELEASE_WORKFLOW.exists(), "there is no release workflow; the published artifact is ungated"
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'tags: ["v*"]' in workflow
    assert "id-token: write" in workflow, "Trusted Publishing needs an OIDC token"
    assert "pypa/gh-action-pypi-publish" in workflow
    assert "twine check" in workflow
    # An API token in the workflow would be a credential that outlives the run and can
    # push a release nothing links back to a commit.
    assert "PYPI_API_TOKEN" not in workflow
    assert "password:" not in workflow


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
