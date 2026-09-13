# DEVELOPMENT_PROTOCOL.md

## Status and authority

Protocol version: `0.3`  
Project: **1337 Security Workbench by Fuzzy Technologies**

This file is the persistent development contract for the repository. AI agents, Codex sessions, IDE assistants, scripts, CI jobs, and human contributors are expected to follow it.

This protocol is owner-controlled. Automated agents must not modify it unless the project owner explicitly asks to change this file.

## 1. Core principle

The development order is:

```text
architecture/contract
→ implementation
→ tests
→ evidence
→ documentation/changelog
→ review
```

Do not damage an already working source of truth or public contract merely to simplify an intermediate refactor.

A change is not complete because the code looks correct. Completion requires the applicable tests and evidence.

## 2. Repository identity and language

The repository identity is **1337 Security Workbench by Fuzzy Technologies**.

Canonical repository language is English:

- source code;
- comments and docstrings;
- Markdown documentation;
- commit messages;
- prompts and agent instructions;
- schemas;
- CLI commands;
- API names;
- machine-readable identifiers.

Localization resources are the only normal exception. Canonical commands and APIs remain English.

## 3. Branching, project tracking, and release flow

Canonical branches:

- `master` — stable public state; tagged commits identify product releases, while qualifying documentation/site publications may be untagged;
- `develop` — integration branch for the next release;
- `feature/<name>` — feature/work-item branches from `develop`;
- `fix/<name>` — non-release fixes from `develop`;
- `release/<version>` — release stabilization;
- `hotfix/<name-or-version>` — urgent fix from `master`.

Normal flow:

```text
feature/* or fix/* → develop → release/X.Y.Z → master → tag vX.Y.Z
                                           └──────────→ develop (back-merge)
```

Hotfix flow:

```text
master → hotfix/* → master → tag
                    └──────→ develop
```

Detailed protected-branch, merge, release, tag, hotfix, and documentation/site publication rules are defined in [`docs/RELEASE_WORKFLOW.md`](docs/RELEASE_WORKFLOW.md).

Until real customer support obligations exist, do not create multiple parallel supported release lines without an explicit owner decision.

### Project planning and traceability

GitHub planning follows this hierarchy:

```text
Milestone
└── Feature issue          native Type: Feature
    ├── Task issue         native Type: Task + native sub-issue
    ├── Task issue         native Type: Task + native sub-issue
    └── Pull request(s)
```

Rules:

- A milestone represents a major roadmap outcome and owns its feature/issues for planning and delivery tracking.
- The milestone's GitHub due date is the canonical schedule. Do not duplicate target dates in issue bodies when they can drift from the milestone.
- Native GitHub Issue Type is the canonical work classification: `Feature`, `Task`, or `Bug`.
- Native GitHub Sub-issues are the canonical Feature → Task hierarchy. Do not maintain duplicate `Parent feature: #NN` or `Child tasks: #NN` lists in issue bodies.
- Issue labels are supplementary metadata only. Do not duplicate native Issue Type with `feature`, `task`, or `bug` labels on issues.
- Pull requests may continue to use the owner-approved labels because PRs do not have Issue Type.
- Do not create new issue labels merely for convenience; use the owner-approved repository label set unless the owner explicitly requests a new label.
- Feature and task titles should include the roadmap identifier while milestones are active, for example `M2 Feature: Tool Adapter SDK` and `M2 Task: Implement typed ToolAdapter contract`.
- Every feature and task must belong to the appropriate GitHub milestone.
- Backlog feature/task issues remain unassigned. Assignment means active work, not roadmap ownership.
- When work on one or more task issues actually begins, assign the project owner (`Tim55667757`) to those active task issues. If work is explicitly returned to the backlog before completion, remove the assignee.
- Pull requests must reference the task(s) and feature(s) they implement and should use the milestone of the primary owning task/feature unless the PR is explicitly cross-milestone.
- A pull request that fully completes a task may use `Closes #NN` or `Fixes #NN` in the PR body. Do not use closing keywords when the PR only partially advances the task.
- After a human merge into `develop`, the `Close merged tasks` workflow closes only open repository issues named by an explicit, standalone `Closes #NN`, `Fixes #NN`, or `Resolves #NN` line in the merged PR body. `Refs #NN` and ordinary mentions never close work.
- Ordinary intermediate commits reference their owning issue without closing it.
- When a task implementation is ready for owner review, add a short plain-English issue comment describing what changed, what the change enables, and how it was actually verified. Keep it readable for a human; use a small Markdown table only when it improves clarity.
- A task remains open while its completing PR is in review. Normal completion is PR merge → Task closed.
- A feature is closed only after its required native sub-issues are complete and its feature-level acceptance criteria are satisfied.
- Before feature closure, add a concise feature-level acceptance comment when useful to summarize the completed capability and evidence.
- Milestone target dates are planning targets, not evidence of completion. A milestone is complete only when the tracked work and applicable acceptance evidence are actually complete.
- The public README contains only a high-level roadmap. Detailed implementation planning belongs in GitHub milestones/issues and internal planning artifacts.
- Public repository issues and documentation must describe public contracts and generic extension boundaries only; do not expose proprietary implementation details, secrets, or confidential roadmap internals.

### Pull request labels

Use only the owner-approved repository label set. PR labels describe the actual content of the PR rather than merely mirroring the parent issue type.

- `feature` — new product/subsystem capability or meaningful extension of an existing capability;
- `bug` — defect correction;
- `documentation` — documentation-only or materially documentation-dominant work;
- `task` — engineering infrastructure, testing, maintenance, refactoring, packaging, or another implementation task not better represented by `feature`, `bug`, or `documentation`;
- `duplicate` — only when the item is genuinely a duplicate; normally not an implementation-PR label.

Multiple existing labels may be used when each is materially true. Do not create a new label simply to describe one PR.

### Pull requests

- No normal direct push to `master` or `develop`.
- Open work PRs against `develop` unless a release/hotfix workflow or the documentation/site publication exception in `docs/RELEASE_WORKFLOW.md` explicitly requires another base.
- Draft PRs are the normal place for work still being implemented or validated.
- CI and relevant tests must pass before merge once those checks exist.
- Human owner review is the normal merge gate.
- Automated agents must not self-merge unless explicitly instructed for that specific PR.
- Force-push and history rewriting on protected branches are prohibited.
- Default merge method for ordinary work PRs is Squash and merge; exceptions are defined in `docs/RELEASE_WORKFLOW.md`.

## 4. Commit messages

Do not use Conventional Commits prefixes such as `feat:`, `fix:`, or `chore:`.

For cross-project/shared work:

```text
1337: concise English description (#NN)
```

For module-owned work, use the module name as the prefix:

```text
1337 Scope: concise English description (#NN)
1337 Scan: concise English description (#NN)
1337 Intel: concise English description (#NN)
1337 Report: concise English description (#NN)
1337 Trace: concise English description (#NN)
Fuzzy Striker: concise English description (#NN)
```

Release-specific product work may include the release version when useful:

```text
1337 vX.Y.Z: concise English description (#NN)
```

Issue references normally appear at the end of the subject as `(#NN)` so the human-readable action remains first and GitHub still creates the link.

If one coherent commit legitimately contributes to several issues, either list the references in the subject when concise or use the commit body:

```text
Refs #45
Refs #46
```

Do not use `Closes #NN`, `Fixes #NN`, or equivalent closing keywords in ordinary intermediate commits. Closing semantics belong in the pull request that actually completes the task.

A commit should represent one coherent logical change. Infrastructure repair, behavior changes, broad refactoring, and unrelated documentation cleanup should not be mixed.

### Work slicing and commit cadence

- Commit after a coherent logical implementation slice has been completed and the applicable targeted tests/evidence for that slice have been checked.
- A non-trivial task should normally contain multiple small logical commits when that improves reviewability, diagnosis, or rollback.
- Avoid both one giant catch-all commit and mechanical commit spam for every touched file or trivial edit.
- Related tiny edits may be combined into one coherent commit; unrelated work must remain separate.
- Do not fabricate, backdate, randomize, or deliberately delay commit timestamps to imitate a human contributor. Repository history must reflect real execution time and real work boundaries.

## 5. Change discipline and public compatibility

- Keep each change narrow and reviewable.
- Architecture-impacting work requires an ADR/design decision before or together with implementation.
- Refactoring is behavior-preserving unless the task explicitly says otherwise.
- Style-only changes must not alter identifiers, evaluation order, expressions, conditions, call order, public contracts, or runtime behavior.
- Before deleting a module, function, file, field, command, schema member, or compatibility layer, inspect references and prove that the removal is safe.
- Do not silently remove fallbacks, guards, validation, logging, audit evidence, or tests.
- Do not add `TODO`, `FIXME`, `TEMP`, or `HACK` to tracked source.
- Avoid speculative abstractions. Introduce a layer when it has a concrete contract or at least two credible consumers.
- Public compatibility boundaries, stability classes, schema-version rules, and extension-consumer expectations are defined in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).
- A source symbol, import path, JSON field, route, or file format is not automatically public/stable merely because it is visible. Stability must be explicitly declared.
- Changes to Stable public contracts require compatibility impact review and the version/schema transition required by the compatibility policy.

## 6. Python house style

Python is the primary orchestration, CLI, automation, adapter, API, testing, and data-pipeline language.

### 6.1. General style

- Use 4-space indentation.
- Use modern Python with explicit, readable control flow.
- Use type hints for public interfaces and important internal contracts.
- Prefer `dataclass`, `Protocol`, `TypedDict`, enums, or validated models where a real data contract exists.
- Prefer `pathlib.Path` over ad-hoc string path manipulation.
- Use context managers for files, locks, temporary resources, and managed processes.
- Keep imports grouped as standard library, third-party, then project-local imports.
- Avoid wildcard imports.
- Avoid hidden global mutable state unless it is a deliberate, tested process-wide registry.
- Do not use bare `except:`.
- Exceptions should preserve the original cause and add actionable context.
- Security or validation boundaries fail closed unless a documented contract explicitly defines degradation/fallback behavior.
- Do not use `eval`/`exec` for configuration or plugin dispatch.
- For subprocesses, prefer argument arrays and `shell=False`; shell invocation requires an explicit justified boundary.
- JSON written by project code must be standards-compliant; do not emit `NaN`, `Infinity`, or `-Infinity`.

### 6.2. Naming

Default Python naming:

- modules/functions/variables: `snake_case`;
- classes/protocols/enums: `PascalCase`;
- constants: `UPPER_CASE`;
- private implementation details: leading `_`.

Preserve externally defined naming where it is part of a contract. Do **not** mechanically rename:

- CLI arguments and command names;
- JSON/TOML/YAML fields;
- archive member names;
- external schemas;
- dynamic import entry points;
- callback names;
- third-party API fields;
- compatibility contracts.

External contract correctness has priority over cosmetic naming normalization.

### 6.3. Formatting

`ruff format` is **not** the canonical formatter contract.

Ruff may be used for lint/static checks, but style-only work must not mechanically rewrite protected interfaces or behavior.

Specific house rule retained from existing Fuzzy Technologies Python projects:

> After a completed multi-line `for` block, insert a blank line before the next independent statement or block when that line is no longer part of the loop/control flow.

Do not mechanically insert blank lines inside a logically continuous construct.

Prefer readable source over clever compression. A dense one-liner or nested comprehension should not replace straightforward control flow when it reduces debuggability or evidence clarity.

### 6.4. Functions and modules

- Keep one clear responsibility per function/module.
- Avoid wrapper functions that add no contract, validation, or abstraction value.
- Separate pure parsing/transformation from I/O when practical.
