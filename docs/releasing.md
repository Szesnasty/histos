# Releasing Histos

PyPI files and version numbers cannot be replaced. Treat a release as an approval
event, not as the side effect of pushing a tag.

## One-time prerequisites

Before the first release:

1. Make the GitHub repository public. The package metadata and PyPI README deliberately
   link to the source, documentation, issues and changelog on GitHub.
2. Create a GitHub environment named exactly `pypi`. Add a required reviewer if the
   repository plan supports deployment protection rules.
3. Configure the PyPI Trusted Publisher for project `histos`, owner `Szesnasty`,
   repository `histos`, workflow `release.yml` and environment `pypi`. Do not leave the
   environment as `(Any)` after the project exists.
4. Confirm that the repository permits the Release workflow's `GITHUB_TOKEN` to create
   the Release Please pull request. Keep default token permissions read-only; the
   workflow grants write permissions only to the release-preparation job.

No PyPI API token belongs in GitHub. Publication uses the short-lived OIDC identity of
the `publish` job.

## Normal release

1. Push conventional commits to `main`. This may create or update a Release Please PR;
   it does not publish a package.
2. Review the proposed version, changelog, manifest and CI results.
3. Merge the Release Please PR only when the release is approved. That merge is the
   release signal: Release Please creates the tag and GitHub Release in the same run,
   then the workflow lints, builds, checks metadata and runs the suite against the
   wheel before requesting a PyPI OIDC token.
4. Verify the PyPI project, provenance and hashes recorded by the workflow.

Do not create or push a release tag by hand. A tag push does not trigger publication.

## Recovery after the tag exists

If the GitHub tag/Release was created but a later build or PyPI step failed, keep the
tag immutable. Fix only a transient external condition, then manually dispatch the
`Release` workflow with `release_tag` set to that existing `vX.Y.Z` tag. The workflow
checks that the checkout is exactly at that tag and that the tag, source version and
built filenames agree before it can publish.

If code or metadata must change, do not reuse the version. Make the fix on `main` and
release a new version through the normal Release Please flow.
