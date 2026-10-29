# Branch and Release Workflow

This document defines the repository-level branch, merge, release, and tag workflow for **1337 Security Workbench by Fuzzy Technologies**.

It complements `DEVELOPMENT_PROTOCOL.md`. If these documents ever conflict, stop and resolve the conflict before continuing release work.

## Branch roles

| Branch pattern      | Purpose                                          | Normal source             | Normal destination |
| ------------------- | ------------------------------------------------ | ------------------------- | ------------------ |
| `master`            | Stable public state; tagged commits are releases | release/hotfix/docs paths | tag or publication |
| `develop`           | Integration branch for the next release          | `feature/*`, `fix/*`      | `release/*`        |
| `feature/<name>`    | Product, subsystem, governance, or feature work  | `develop`                 | `develop`          |
| `fix/<name>`        | Non-release defect correction                    | `develop`                 | `develop`          |
| `release/<version>` | Release stabilization for one version            | `develop`                 | `master`           |
| `hotfix/<name>`     | Urgent released-state correction                 | `master`                  | `master`           |

Do not use roadmap IDs as long-lived architecture owners. Roadmap identifiers may appear in issue titles and planning metadata, while branch names describe the actual change.

## Protected branches

`master` and `develop` are protected repository branches.

The current baseline requires:

- changes through pull requests rather than normal direct pushes;
- review conversations resolved before merge;
- branch deletion blocked;
- force-push/non-fast-forward updates blocked;
- owner/admin bypass reserved for exceptional recovery, not normal development.

Required CI/status checks are enabled when the corresponding checks exist and are stable enough to become merge gates. A missing CI system must never be represented as a passing check.

## Normal development flow

```text
issue/task
   ↓
feature/* or fix/*
   ↓
Draft PR → review/evidence → Ready for review
   ↓
develop
```

Rules:

1. Create the work branch from current `develop`.
2. Keep commits small and logically coherent; reference the owning issue as `(#NN)`.
3. Intermediate commits must not use closing keywords.
4. Open a Draft PR early enough for the full diff and discussion to remain reviewable.
5. Add/update tests and evidence appropriate to the change.
6. Move the PR to Ready for review only after the task acceptance criteria are satisfied.
7. Use `Closes #NN`/`Fixes #NN` in the PR body only for work the PR actually completes.
8. Merge after the applicable review and required CI. Ordinary implementation PRs into `develop` follow the standing owner-approved autonomous integration cycle in `DEVELOPMENT_PROTOCOL.md`; release and `master` decisions retain their separate owner requirements.

### Merge method

For normal feature/task PRs into `develop`, **Squash and merge is the default**. The PR retains the detailed implementation commits for review, while `develop` receives one coherent integration commit.

Use a merge commit instead when preserving the internal commit graph is materially useful for release, audit, or multi-branch history. Rebase merge is allowed only when it improves history without weakening traceability.

The final integration commit title should follow the project convention, for example:

```text
1337: add public compatibility contract (#7)
```


## Documentation and GitHub Pages publication

Product releases and public documentation do not need the same publication cadence.
A commit on `master` is therefore not automatically a product release.

**Annotated `vX.Y.Z` tags identify product releases.** Between product releases,
documentation-only and static-site-only commits may be merged to `master` without
creating a new version tag or GitHub Release when all conditions below are satisfied.

Typical eligible files include `README.md`, `docs/`, `index.md`, Jekyll
configuration/layouts, and static site assets. Eligibility is determined by the
actual diff, not by the path name alone.

A documentation/site publication PR to `master` must satisfy all of these rules:

1. The diff changes only human-facing documentation or static-site presentation.
   It must not change runtime/product behavior, package/version metadata,
   dependencies or lockfiles, executable CI behavior, public machine-readable
   contracts, security/authorization policy, persisted data/schema, or release
   artifacts.
2. The publication branch is created from the current `master` so the PR contains
   only the intended public-documentation/site delta. If the content was first
   accepted in `develop`, port only the accepted publication files into the
   dedicated branch; do not merge unrelated `develop` work into `master`.
3. The PR body explicitly states **Documentation/site publication — no product
   release** and identifies the latest tagged product release whose capability
   boundary the page describes.
4. Claims about implemented capability, current version, security boundaries, and
   roadmap work must remain consistent with the latest tagged release and stable
   public contracts.
5. Applicable CI and static-site/document checks must pass. A documentation-only
   exception does not bypass protected-branch review or required checks.
6. Do not create a SemVer bump, release tag, GitHub Release, or changelog Patch
   solely to publish qualifying documentation/site changes.
7. After publication, keep `develop` consistent. If the same change is not already
   present there, propagate the `master` publication commit back through a PR.

The intended flow is:

```text
normal product work
feature/* → develop → release/X.Y.Z → master → tag vX.Y.Z

documentation/site work
docs change → develop
                 \
                  \ accepted publication content
                   ↓
          docs/* from current master
                   ↓ PR
                 master
                   ↓
             GitHub Pages

             no version tag
             no GitHub Release
```

This exception exists to publish accurate project information and GitHub Pages
updates promptly. It must not be used to smuggle product behavior or unreleased
contracts into `master`.

## Release flow

A release is cut only from an accepted `develop` state.

```text
develop
   ↓
release/X.Y.Z
   ↓
release validation + version/changelog finalization
   ↓ PR
master
   ↓
annotated tag vX.Y.Z
   ↓
GitHub Release from the existing tag
   ↓ PR/back-merge
 develop
```

Release procedure:

1. Create `release/X.Y.Z` from the exact accepted `develop` commit.
2. Freeze unrelated feature work out of the release branch.
3. Run the complete configured release gates after the final tracked change.
4. Finalize release metadata, including package/version metadata once packaging exists, plus the strict changelog entry.
5. Open a PR from `release/X.Y.Z` to `master`.
6. Review the exact release diff and evidence.
7. Merge to `master` without bypassing required checks.
8. Wait for the actual required `master` push jobs to finish successfully on the
   exact resulting release SHA, including the deployed documentation. A skipped
   job, PR run or workflow summary alone does not satisfy this requirement.
   For v0.3.0, also complete the [GitHub CI onboarding pre-tag platform gate](CI_QUICKSTART.md#github-pre-tag-platform-gate):
   dispatch the exact public-template workflow twice on the same accepted master
   SHA and fixed reviewed Python image, with approval false then true. Inspect
   original artifacts, denied-before-target behavior, successful offline reopen
   and explicit owned-resource teardown. The denied workflow must fail with
   actual exit 3. Hold finalizer/tag dispatch until both observed outcomes are
   accepted; ordinary master checks alone do not establish this manual gate.
   In a trusted local Git checkout, create the annotated tag **`vX.Y.Z` on the
   resulting `master` release commit**, then push that tag. Do not use the GitHub
   Release UI to create the tag.

   ```bash
   git tag -a vX.Y.Z <master-release-sha> -m "1337 Security Workbench vX.Y.Z"
   git push origin vX.Y.Z
   ```

9. Verify the tag before creating the GitHub Release:

   ```bash
   git cat-file -t vX.Y.Z
   git rev-parse vX.Y.Z^{}
   ```

   The first command must print `tag`; the second must print the exact resulting
   `master` release SHA. A `commit` result is a lightweight tag and fails this
   release requirement.
10. The tag-triggered `release.yml` workflow validates the annotated source and
    actual master job evidence, builds the sdist and wheel once, and verifies the
    clean installed wheel before any upload. Its protected `pypi` environment
    gates publication of those same bytes through Trusted Publishing.
11. The workflow performs a new clean install of the exact version from PyPI,
    verifies the downloaded wheel hash against the original build, and exercises
    the installed owned demo, target teardown and offline reopen/export. Only
    after that succeeds does it create the GitHub Release from the existing tag,
    with the accepted release card, distributions, checksums and original build
    evidence. Do not create another tag or release through the UI.
12. Propagate the released `master` state back to `develop` through a PR so release-only fixes/metadata cannot be lost.
13. Delete the release branch after the back-merge is complete unless a specific support reason requires retaining it.

### PyPI publisher setup and immutable delivery

Before pushing the first final release tag, the project owner must configure the
PyPI Trusted Publisher (or Pending Publisher for an uncreated project):

| Setting            | Required value       |
| ------------------ | -------------------- |
| PyPI project       | `1337`               |
| GitHub owner       | `Fuzzy-Technologies` |
| Repository         | `1337`               |
| Workflow filename  | `release.yml`        |
| GitHub environment | `pypi`               |

Protect the GitHub `pypi` environment with the designated release reviewer and
restrict it to release tags. PyPI account creation, project/name ownership,
two-factor authentication and publisher registration are owner-side account
operations. A public project lookup returning 404 does not prove name
availability, ownership or reservation; Pending Publishers do not reserve names.
No long-lived PyPI password or API token belongs in repository secrets.

The release tool rejects lightweight tags, source/version drift, stale or skipped
master gates, changed artifacts and an index wheel whose hash differs from the
original build. The allowlist in `tools/release_delivery.py` binds actual named
jobs and steps from the latest exact-SHA master push attempt, rather than counting
unrelated diagnostic jobs. When canonical job names change, update this contract
and its tests before tagging.

`SHA256SUMS` covers both distributions, the rendered card and evidence; its own
SHA-256 is passed independently between jobs. Every consumer revalidates the
handoff. The publisher has no source checkout or build/install step and receives
OIDC authority only within `pypi`. It uploads the wheel and sdist with PEP 740
attestations. Its `skip-existing: false` setting intentionally refuses a version
that is already present. GitHub release publication has separate contents-write
authority and uses `gh release create --verify-tag`; it cannot create the tag as
a side effect.

The GitHub assets include the exact wheel and sdist, `SHA256SUMS`,
`release-manifest.json`, `source.json`, `master-checks.json`, `clean-install.json`
and `distribution-metadata.json`, plus `1337-X.Y.Z-api-docs.tar.gz` and its
`1337-X.Y.Z-api-docs.manifest.json`. The API pair is downloaded by immutable
artifact ID from the accepted master documentation run and its exact attempt's
`api-docs-COMMIT-ATTEMPT` artifact. The shared strict archive verifier binds its
original bytes, complete locale inventory, commit, tree, version and timestamp
before the copied pair enters the sealed bundle. No documentation rebuild or
render runs in the release workflow, and no documentation archive enters PyPI.
The original post-PyPI install report and demo
evidence remain attached to the same Actions run as `pypi-install-evidence`.
`docs/releases/vX.Y.Z.md` is the reviewed card source; its validation marker is
replaced only by the actual accepted gate links and installed-wheel result.

Release publication is not an atomic transaction across services. If upload or
postpublication verification fails, retain the failed run and original artifacts,
inspect which immutable files actually reached PyPI, and resolve the failure
before marking delivery complete. Do not silently retry the whole release,
enable `skip-existing`, overwrite/move a tag, or rebuild different bytes under
the same version. If a published artifact is defective, document the outcome and
cut an owner-approved corrective version. A transport-only publication recovery
must reuse the independently verified original artifact and require a reviewed,
explicit recovery procedure.

M2 acceptance that requires installation from PyPI is complete only after the
actual public-index installation and installed product checks pass. Source CI,
local wheel installation and a successful upload alone are separate evidence.
Pages publication remains independent; release-version documentation is prepared
and validated before the release merge, then the exact master deployment must
pass before tagging.

## Published release notes

GitHub Release notes are a public product interface. They must lead with an
immediately understandable `## Digest`: one short paragraph explaining what the
release gives a human reader and its maturity boundary.

The remaining detail uses this stable structure when applicable:

1. `## What's Changed`, organized under concise categories such as Added,
   Changed, Fixed, Documentation, and Security;
2. `## Validation`, with the exact relevant gates and their actual results;
3. `## Breaking Changes`, stating `None` explicitly when there are none;
4. `## Try it from source`, with commands that check out the exact release tag;
5. `## Notes`, covering pre-release status, security boundaries, known
   limitations, upgrade guidance, and immediate follow-up work.

Release notes must distinguish implemented behavior from roadmap direction and
avoid marketing claims that cannot be demonstrated by the released artifact.

### Release-card template

Use the following structure, omitting only sections that are genuinely not
applicable. Keep the Digest to one short, human-readable paragraph.

````markdown
## Digest

<What a reader gains in this version and its maturity boundary.>

## What's Changed

### Added

- <Implemented capability with a useful public link when available.>

### Changed

- <Implemented change.>

### Documentation

- [Vision](https://github.com/Fuzzy-Technologies/1337/blob/vX.Y.Z/docs/VISION.md)
  and other public references relevant to this release.

### Security

- <Implemented security boundary or hardening.>

## Validation

- [Exact GitHub Actions run](https://github.com/Fuzzy-Technologies/1337/actions/runs/<run-id>)
  — <actual result and scope>.

## Breaking Changes

None.

## Try it from source

```sh
git clone --branch vX.Y.Z --depth 1 https://github.com/Fuzzy-Technologies/1337.git
cd 1337
python -m pip install uv==0.11.33
uv run --locked 1337 help
uv run --locked --extra dev 1337-dev check
```

## Notes

<Pre-release status, known limitations, and immediate follow-up work.>
````

Use readable Markdown links for a public artifact, pull request, issue, or CI
run when the link supplies useful evidence or a meaningful next step. Links to
release content must resolve against the released tag (`vX.Y.Z`), not a moving
branch. Do not add decorative links or make a roadmap item look implemented.

## Version and tag invariants

- Release versions use Semantic Versioning: `X.Y.Z`.
- Git release tags use exactly `vX.Y.Z`.
- A published release tag is immutable: do not move or silently recreate it.
- Do not create the release tag before the `master` release commit exists.
- The tag, changelog version, package metadata, and release artifact version must agree once those artifacts exist.
- A failed or incomplete release attempt does not reuse an already published version/tag.
- Pre-release identifiers, when introduced, must use valid SemVer syntax and be explicitly documented.
- Not every `master` commit is a product release: qualifying documentation/site publication commits may be untagged under the dedicated exception above. The latest product release remains the latest valid annotated `vX.Y.Z` tag.

## Hotfix flow

Hotfixes start from the released state, not from `develop`.

```text
master
   ↓
hotfix/<name>
   ↓ PR
master → tag vX.Y.Z
   ↓ PR/back-merge
 develop
```

Procedure:

1. Branch from current `master`.
2. Make the smallest safe correction with targeted regression tests/evidence.
3. Open a PR to `master` and complete the normal review gate.
4. Merge, create the next valid release tag on the resulting `master` commit, and publish the corresponding release note/changelog entry.
5. Propagate the hotfix back to `develop` through a PR.

Never fix only `master` and leave `develop` divergent.

## Issue and feature completion

- A Task remains open while its PR is under development or review.
- The completing PR may close its Task automatically with a closing keyword.
- A Feature is complete only when its required native sub-issues are complete and its feature-level acceptance criteria/evidence are satisfied.
- Milestone dates are planning metadata, not completion evidence.

## Exceptional bypass

Admin/owner bypass exists for repository recovery and other explicit exceptional cases. If bypass is used, record why it was necessary and restore the normal protected-branch path immediately afterward.

Routine development, agent work, release pressure, or convenience are not valid bypass reasons.
