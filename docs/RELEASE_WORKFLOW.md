# Branch and Release Workflow

This document defines the repository-level branch, merge, release, and tag workflow for **1337 Security Workbench by Fuzzy Technologies**.

It complements `DEVELOPMENT_PROTOCOL.md`. If these documents ever conflict, stop and resolve the conflict before continuing release work.

## Branch roles

| Branch pattern        | Purpose                                              | Normal source             | Normal destination |
| --------------------- | ---------------------------------------------------- | ------------------------- | ------------------ |
| `master`              | Stable/released repository state                     | `release/*`, `hotfix/*`   | release tag        |
| `develop`             | Integration branch for the next release              | `feature/*`, `fix/*`      | `release/*`        |
| `feature/<name>`      | Product, subsystem, governance, or feature work      | `develop`                 | `develop`          |
| `fix/<name>`          | Non-release defect correction                        | `develop`                 | `develop`          |
| `release/<version>`   | Release stabilization for one version                | `develop`                 | `master`           |
| `hotfix/<name>`       | Urgent released-state correction                     | `master`                  | `master`           |

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
8. Merge only after the human owner accepts the change.

### Merge method

For normal feature/task PRs into `develop`, **Squash and merge is the default**. The PR retains the detailed implementation commits for review, while `develop` receives one coherent integration commit.

Use a merge commit instead when preserving the internal commit graph is materially useful for release, audit, or multi-branch history. Rebase merge is allowed only when it improves history without weakening traceability.

The final integration commit title should follow the project convention, for example:

```text
1337: add public compatibility contract (#7)
```

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
release notes
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
8. Create the annotated tag **`vX.Y.Z` on the resulting `master` release commit**.
9. Publish release notes from the accepted changelog/release evidence.
10. Propagate the released `master` state back to `develop` through a PR so release-only fixes/metadata cannot be lost.
11. Delete the release branch after the back-merge is complete unless a specific support reason requires retaining it.

## Published release notes

GitHub Release notes are a public product interface. They must lead with an
immediately understandable `## Digest`: one short paragraph explaining what the
release gives a human reader and its maturity boundary.

The remaining detail uses this stable structure when applicable:

1. `## What's Changed`, organized under concise categories such as Added,
   Changed, Fixed, Documentation, and Security;
2. `## Validation`, with the exact relevant gates and their actual results;
3. `## Breaking Changes`, stating `None` explicitly when there are none;
4. `## Notes`, covering pre-release status, security boundaries, known
   limitations, upgrade guidance, and immediate follow-up work.

Release notes must distinguish implemented behavior from roadmap direction and
avoid marketing claims that cannot be demonstrated by the released artifact.

## Version and tag invariants

- Release versions use Semantic Versioning: `X.Y.Z`.
- Git release tags use exactly `vX.Y.Z`.
- A published release tag is immutable: do not move or silently recreate it.
- Do not create the release tag before the `master` release commit exists.
- The tag, changelog version, package metadata, and release artifact version must agree once those artifacts exist.
- A failed or incomplete release attempt does not reuse an already published version/tag.
- Pre-release identifiers, when introduced, must use valid SemVer syntax and be explicitly documented.

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
