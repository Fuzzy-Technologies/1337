# ADR 0113: Immutable release distribution delivery

## Status

Accepted for implementation under the owner's explicit M2/v0.3.0 release
instruction. Actual publication still requires the validated release commit,
owner-configured Trusted Publisher and protected `pypi` environment. This source
decision does not claim a published package or completed M2 acceptance.

## Decision

An existing annotated `vX.Y.Z` tag on the exact current `master` commit starts
the single release workflow. It refuses lightweight tags, source/version/lock
drift and dirty source. The current format intentionally accepts final numeric
versions only; a future prerelease format requires a separate reviewed decision.

Before building, the workflow reads the latest exact-master push attempts for
the six existing master workflows. Named required jobs and their actual required
execution steps must be successful. A successful workflow containing skipped
jobs is insufficient. Missing, pending, failed or incomplete evidence refuses;
there is no polling loop or old-success fallback. Finish master CI before
creating the release tag.

The read-only build job creates one sdist and its wheel. A clean environment
outside the source checkout installs that exact wheel and executes the installed
CLI, plan denial, approved owned demo, target teardown, offline reopen/export and
existing-root refusal. Source, actual master validation, installed behavior,
distribution metadata and the release card are sealed with original hashes.

An immutable same-run Actions artifact ID and independent checksum-file digest
bind the handoff. The separate Linux `pypi` job downloads and verifies these
same distributions, then uses the checksum-pinned official PyPA publisher with
OIDC and PEP 740 attestations. Only this job receives `id-token: write`; it has
no repository write token, build, installation or source-checkout step. Existing
distribution versions are never silently skipped or overwritten.

A subsequent fresh environment installs the exact version from the public PyPI
index without cache, verifies the installed wheel hash against the original
release manifest, and repeats the bounded product smoke. Only then can the
contents-write GitHub job create the release card and attach the unchanged
wheel/sdist and evidence. It verifies the existing annotated master tag again
and uses `gh release create --verify-tag`; it neither creates a tag nor updates
an existing GitHub Release.

## Owner configuration

The PyPI project name is `1337` unless the owner resolves an availability conflict
before release composition. Configure the publisher for repository owner
`Fuzzy-Technologies`, repository `1337`, workflow `release.yml`, environment
`pypi`. The GitHub environment must restrict release tags and require owner
approval. A pending publisher does not reserve a project name. No API token,
password, or credential file belongs in this repository.

## Failure and recovery

Registry publication is irreversible. A successful PyPI upload followed by failed
installation or GitHub publication remains an incomplete release; retain the
original artifacts and recover only the failed downstream job after diagnosis.
Do not rerun the upload with `skip-existing`, rebuild different bytes under the
same version, move an annotated tag, or treat an old artifact as fresh evidence.
If source changes are necessary after publication, choose a new version.

The existing Pages workflow remains a distinct protected-master publication
surface. Its source gate is included in release acceptance; versioned rendering
and three-language onboarding content are owned by their documentation changes.
